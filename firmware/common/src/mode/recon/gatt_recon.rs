//! No-secret GATT reconnaissance loop.
//!
//! The radio is time-sliced at the connection level: one link is serviced to
//! completion, then the next eligible advertiser is selected from the next scan
//! window. A successful service-discovery pass is cooled down; connect or
//! discovery failures stay eligible so transient timing and RF problems can be
//! observed again.

use core::fmt::Write;

use embassy_time::Instant;

use crate::central::{
    CONN_AA, Candidate, Conn, ConnectStats, MAX_SERVICES, SURVEY_ROUNDS, configure_conn_radio,
    discover_services, exchange_mtu, pick_access_address, pick_conn_params, randomize_our_addr,
    try_connect_rounds,
};
use crate::hal::radio::{configure_ble_with_maxlen, ensure_disabled};
use crate::{Rng, led};

use super::{
    DeviceEntry, PARAMS, Phase, ProbeState, RecentRing, TABLE, close, flash, log_captured,
    mark_recent, pick_candidate, refresh_seen, scan, set_phase, stamp, track,
};

fn log_name(name: &[u8]) {
    ulogf!("rprobe: name_probe result=accepted len={}\r\n", name.len());
    if name
        .iter()
        .all(|&byte| byte.is_ascii_graphic() || byte == b' ')
        && let Ok(text) = core::str::from_utf8(name)
    {
        let mut line = crate::decoder::LogStr::new();
        let _ = write!(line, "rprobe: name_probe value_ascii=\"{}\"\r\n", text);
        crate::decoder::emit(line);
    } else {
        ulogf!("rprobe: name_probe value_hex len={}\r\n", name.len());
        crate::decoder::hexdump(name, 0, 8);
    }
}

fn log_name_probe_status(status: &super::gatt_probe::NameProbe) {
    let message = match status {
        super::gatt_probe::NameProbe::Absent => "absent",
        super::gatt_probe::NameProbe::Denied(_) => "denied",
        super::gatt_probe::NameProbe::NoReply => "no_reply",
        super::gatt_probe::NameProbe::Unexpected(_) => "unexpected",
        super::gatt_probe::NameProbe::Found(_) => return,
    };
    match status {
        super::gatt_probe::NameProbe::Denied(code) => ulogf!(
            "rprobe: name_probe result={} err=0x{:02X} ({})\r\n",
            message,
            code,
            crate::central::att_error_name(*code)
        ),
        super::gatt_probe::NameProbe::Unexpected(opcode) => ulogf!(
            "rprobe: name_probe result={} att=0x{:02X}\r\n",
            message,
            opcode
        ),
        _ => ulogf!("rprobe: name_probe result={}\r\n", message),
    }
}

/// Run the generic no-secret recon loop forever.
pub(crate) async fn run() -> ! {
    let mut rng = Rng(0x6D69_6465);
    // SAFETY: the mode is spawned once and this loop is its only table accessor.
    let table = unsafe { &mut *TABLE.0.get() };
    let mut recent: RecentRing = heapless::Vec::new();
    loop {
        set_phase(Phase::Scan);
        ulogf!(
            "rscan: start window={}ms dma_payload_max=254 dma_buffer=256\r\n",
            PARAMS.scan_window_ms
        );
        let (found, adv_seen, filtered) = scan(&mut rng).await;
        refresh_seen(table, &found);
        log_captured(adv_seen, filtered, &found, table.len());
        let Some(index) = pick_candidate(&found, &recent) else {
            ulogf!("rscan: no eligible advertiser; continuing scan\r\n");
            continue;
        };
        let candidate = found[index];
        let entry = DeviceEntry {
            addr: candidate.addr,
            addr_random: candidate.addr_random,
            rssi: candidate.rssi,
            last_seen: Some(stamp()),
            last_probed: None,
            probe_state: ProbeState::Seen,
        };

        let state = probe_one(&mut rng, &entry).await;
        if matches!(state, ProbeState::Probed) {
            mark_recent(&mut recent, candidate.addr, PARAMS.cooldown_ms);
            ulogf!(
                "rprobe: addr={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} cooldown={}ms\r\n",
                candidate.addr[5],
                candidate.addr[4],
                candidate.addr[3],
                candidate.addr[2],
                candidate.addr[1],
                candidate.addr[0],
                PARAMS.cooldown_ms
            );
        } else {
            ulogf!(
                "rprobe: addr={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} retry_eligible=true\r\n",
                candidate.addr[5],
                candidate.addr[4],
                candidate.addr[3],
                candidate.addr[2],
                candidate.addr[1],
                candidate.addr[0]
            );
        }
        track(table, &candidate, state);
    }
}

async fn probe_one(rng: &mut Rng, entry: &DeviceEntry) -> ProbeState {
    let a = entry.addr;
    let start = Instant::now();
    ulogf!(
        "rprobe: begin addr={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} rssi={} addr_type={} mode=no_secret_gatt\r\n",
        a[5],
        a[4],
        a[3],
        a[2],
        a[1],
        a[0],
        entry.rssi,
        if entry.addr_random {
            "random"
        } else {
            "public"
        }
    );

    set_phase(Phase::Enumerate);
    let Some(mut conn) = connect(rng, entry).await else {
        set_phase(Phase::Idle);
        return ProbeState::ProbeFailed;
    };
    // `connect()` returns only after the CONNECT_IND has been sent and the
    // scheduler has allocated this link. `ev_addr` is a reply counter and is
    // zero until the first connection event, so it cannot be used as the
    // connection-success test here.
    let connected = conn.is_active();
    ulogf!(
        "rprobe: link_started={} ev_addr={} elapsed={}ms\r\n",
        connected,
        conn.ev_addr,
        Instant::now().saturating_duration_since(start).as_millis()
    );

    // Read the standard GAP Device Name before the full database walk. Local
    // phones and Macs are identified here and do not consume the expensive
    // characteristic probing pass.
    let name_probe = super::gatt_probe::read_short_name(&mut conn).await;
    if let super::gatt_probe::NameProbe::Found(name) = &name_probe {
        log_name(name);
        if let Some(class) = super::ignored_name_class(name) {
            ulogf!("rprobe: filtered class={} reason=local_device\r\n", class);
            close(&mut conn).await;
            set_phase(Phase::Idle);
            return ProbeState::Probed;
        }
    } else {
        log_name_probe_status(&name_probe);
    }

    let mut services: heapless::Vec<crate::central::Service, MAX_SERVICES> = heapless::Vec::new();
    discover_services(&mut conn, &mut services).await;
    ulogf!(
        "rprobe: discovery services={} elapsed={}ms\r\n",
        services.len(),
        Instant::now().saturating_duration_since(start).as_millis()
    );
    if services.len() == MAX_SERVICES {
        ulogf!(
            "rprobe: discovery services_capacity_reached={} possible_truncation=true\r\n",
            MAX_SERVICES
        );
    }
    if !connected || services.is_empty() {
        ulogf!(
            "rprobe: discovery incomplete connected={} services={}\r\n",
            connected,
            services.len()
        );
        close(&mut conn).await;
        set_phase(Phase::Idle);
        return ProbeState::ProbeFailed;
    }

    let report = super::gatt_probe::run(&mut conn, &services).await;
    ulogf!(
        "rprobe: complete addr={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} services={} chars={} read={}/{} write={}/{} subscribe={}/{} notifications={} elapsed={}ms\r\n",
        a[5],
        a[4],
        a[3],
        a[2],
        a[1],
        a[0],
        report.services,
        report.characteristics,
        report.read_accepted,
        report.readable,
        report.write_accepted,
        report.writable,
        report.subscribe_accepted,
        report.subscribable,
        report.notifications,
        Instant::now().saturating_duration_since(start).as_millis()
    );
    flash(led::WHITE, 1);
    close(&mut conn).await;
    set_phase(Phase::Idle);
    ProbeState::Probed
}

async fn connect(rng: &mut Rng, entry: &DeviceEntry) -> Option<Conn> {
    CONN_AA.store(
        pick_access_address(rng),
        core::sync::atomic::Ordering::Relaxed,
    );
    pick_conn_params(rng);
    randomize_our_addr(rng);
    let candidate = Candidate {
        addr: entry.addr,
        addr_random: entry.addr_random,
        rssi: entry.rssi,
        interest: None,
        cap: None,
    };
    let mut stats = ConnectStats::default();
    ulogf!(
        "rprobe: connect_start rounds={} rssi={} addr_type={}\r\n",
        SURVEY_ROUNDS * 2,
        entry.rssi,
        if entry.addr_random {
            "random"
        } else {
            "public"
        }
    );
    let Some(mut conn) = try_connect_rounds(&candidate, &mut stats, SURVEY_ROUNDS * 2).await else {
        ulogf!(
            "rprobe: connect_fail target={} connectable={} elapsed=connect_budget\r\n",
            stats.target,
            stats.connectable
        );
        flash(led::RED, 1);
        ensure_disabled();
        configure_ble_with_maxlen(254);
        return None;
    };
    configure_conn_radio();
    ulog!("rprobe: mtu_start\r\n");
    exchange_mtu(&mut conn).await;
    ulog!("rprobe: mtu_done\r\n");
    ulogf!(
        "rprobe: connect_ok target={} connectable={}\r\n",
        stats.target,
        stats.connectable
    );
    Some(conn)
}
