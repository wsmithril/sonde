//! Midea-control mode: an active central specialised to Midea appliances — detect,
//! connect, run the control-channel handshake, read status for a minute, move on.
//! Text output straight to the log; LED is the shared state-colour [`drive_indicator`].
//!
//! The generic BLE-central machinery (connect, CSA#1, T_IFS, ATT/GATT walk) is
//! shared with GATT-enum and lives in [`crate::central`]; this module owns
//! everything Midea-specific: a scan/handshake/probe task fleet over one shared
//! radio, an in-memory device table, and the C1→C2→C3 handshake / status decode.

use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Instant, Timer};

use crate::central::{
    ADV_CHANNELS, ATT_HANDLE_VALUE_IND, ATT_HANDLE_VALUE_NTF, ATT_MTU_MAX, CONN_AA, CONN_INTERVAL,
    Candidate, Conn, ConnectStats, MAX_CONSEC_MISS, RX_BUF, Reasm, SURVEY_DWELL_MS,
    att_write_await_notify, conn_event, configure_conn_radio, enumerate, handle_ll_control,
    log_notification, parse_midea_sn, peer_att_reply, pick_access_address, pick_conn_params,
    randomize_our_addr, stage_att, stage_empty, terminate, try_connect, update_flow,
};
use super::drive_indicator;
use crate::decoder::protocol::Decoder as _;
use crate::hal::radio::{configure_ble, ensure_disabled};
use crate::led::Pwm;
use crate::{Rng, decoder, device, led};

// ── Config ────────────────────────────────────────────────────────────────────

/// A fresh discovery round (new random ScanA) every 2 min; each round scans 15 s.
const SCAN_PERIOD_MS: u64 = 120_000;
const SCAN_WINDOW_MS: u64 = 15_000;
/// Drop a device from the active table if unseen this long (recency window).
const ACTIVE_TTL_MS: u64 = 5 * 60 * 1000;
/// Skip re-probing a device whose last probe finished within this window.
const COOLDOWN_MS: u64 = 30 * 60 * 1000;
/// Seconds of passive status listen during a probe.
const MIDEA_PROBE_SECS: u64 = 5;
/// Idle poll cadence for the handshake/probe workers when there is no work.
const IDLE_POLL_MS: u64 = 1000;

const ACTIVE_MAX: usize = 32;
const COOLDOWN_MAX: usize = 64;

// ── Timestamps (Option<NonZeroU64>: ms since boot, None = never) ───────────────

/// Milliseconds since boot as a `NonZeroU64` — the `+1` keeps it non-zero so
/// `Option<NonZeroU64>` gets the niche and `None` cleanly means "never".
fn stamp() -> NonZeroU64 {
    NonZeroU64::new(Instant::now().as_millis() + 1).unwrap()
}
/// ms elapsed since a stamp, or `-1` when never set (for logging).
fn age_ms(t: Option<NonZeroU64>) -> i64 {
    match t {
        Some(t) => (stamp().get() - t.get()) as i64,
        None => -1,
    }
}
/// True if `t` is set and within `window_ms` of now.
fn within(t: Option<NonZeroU64>, window_ms: u64) -> bool {
    matches!(t, Some(t) if stamp().get() - t.get() < window_ms)
}

// ── Device table ──────────────────────────────────────────────────────────────

/// Result of the last handshake / probe attempt.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Never,
    Ok,
    Failed,
}
impl core::fmt::Display for Outcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Outcome::Never => "never",
            Outcome::Ok => "ok",
            Outcome::Failed => "failed",
        })
    }
}

/// One tracked appliance. The handshake credential is derivable from the advert
/// (SN + MAC → advertisData → rootKey), so `handshake_state == Ok` *is* the
/// "credential acquired" flag; the sessionKey is per-connection and not stored
/// (the device rotates its ECDH key every link — see the protocol notes).
#[derive(Clone, Copy)]
struct DeviceEntry {
    sn: [u8; 14],
    addr: [u8; 6],
    addr_random: bool,
    last_seen: Option<NonZeroU64>,
    last_handshaked: Option<NonZeroU64>,
    handshake_state: Outcome,
    last_probed: Option<NonZeroU64>,
    last_probed_state: Outcome,
    /// A task is connecting to it right now — never evict or re-pick it.
    in_flight: bool,
}

struct MideaState {
    active: heapless::Vec<DeviceEntry, ACTIVE_MAX>,
    /// SNs probed recently — skip re-adding them for [`COOLDOWN_MS`].
    cooldown: heapless::Vec<([u8; 14], NonZeroU64), COOLDOWN_MAX>,
}
impl MideaState {
    const fn new() -> Self {
        Self { active: heapless::Vec::new(), cooldown: heapless::Vec::new() }
    }
}

/// The device table, shared by all Midea tasks. Single-threaded executor; the lock
/// is held only for brief synchronous updates, never across a radio op.
static STATE: Mutex<CriticalSectionRawMutex, MideaState> = Mutex::new(MideaState::new());

/// The radio, owned by whichever task is on air. The guard also carries the jitter
/// PRNG, so only the on-air holder draws connection parameters — no `&mut Rng`
/// aliasing across tasks, and a connection is never preempted mid-timing.
static RADIO: Mutex<CriticalSectionRawMutex, Rng> = Mutex::new(Rng(0x6D69_6465));

fn prune_cooldown(st: &mut MideaState) {
    let now = stamp().get();
    let mut i = 0;
    while i < st.cooldown.len() {
        if now - st.cooldown[i].1.get() >= COOLDOWN_MS {
            st.cooldown.swap_remove(i);
        } else {
            i += 1;
        }
    }
}
fn in_cooldown(st: &MideaState, sn: &[u8; 14]) -> bool {
    let now = stamp().get();
    st.cooldown.iter().any(|(s, t)| s == sn && now - t.get() < COOLDOWN_MS)
}

/// Insert or refresh a seen device. Skips devices in cooldown; when the table is
/// full, evicts the oldest entry that is not currently being processed (drops the
/// newcomer if every slot is in-flight).
fn upsert(st: &mut MideaState, c: &Candidate) {
    let Some(sn) = c.sn else { return };
    if in_cooldown(st, &sn) {
        return;
    }
    if let Some(e) = st.active.iter_mut().find(|e| e.sn == sn) {
        e.addr = c.addr;
        e.addr_random = c.addr_random;
        e.last_seen = Some(stamp());
        return;
    }
    if st.active.is_full() {
        let mut oldest: Option<usize> = None;
        for i in 0..st.active.len() {
            if st.active[i].in_flight {
                continue;
            }
            let replace = match oldest {
                None => true,
                Some(j) => age_ms(st.active[i].last_seen) > age_ms(st.active[j].last_seen),
            };
            if replace {
                oldest = Some(i);
            }
        }
        match oldest {
            Some(i) => {
                st.active.swap_remove(i);
            }
            None => return, // every slot busy — leave the newcomer for next round
        }
    }
    let _ = st.active.push(DeviceEntry {
        sn,
        addr: c.addr,
        addr_random: c.addr_random,
        last_seen: Some(stamp()),
        last_handshaked: None,
        handshake_state: Outcome::Never,
        last_probed: None,
        last_probed_state: Outcome::Never,
        in_flight: false,
    });
}

/// Drop devices unseen for [`ACTIVE_TTL_MS`] (except those in flight).
fn evict_stale(st: &mut MideaState) {
    let mut i = 0;
    while i < st.active.len() {
        if !st.active[i].in_flight && !within(st.active[i].last_seen, ACTIVE_TTL_MS) {
            st.active.swap_remove(i);
        } else {
            i += 1;
        }
    }
}

/// Claim the next credential-less, fresh, idle device for handshaking.
fn pick_for_handshake(st: &mut MideaState) -> Option<DeviceEntry> {
    let i = st.active.iter().position(|e| {
        !e.in_flight && e.handshake_state != Outcome::Ok && within(e.last_seen, ACTIVE_TTL_MS)
    })?;
    st.active[i].in_flight = true;
    Some(st.active[i])
}

/// Claim the freshest credentialed, idle, not-recently-probed device.
fn pick_for_probe(st: &mut MideaState) -> Option<DeviceEntry> {
    let mut best: Option<usize> = None;
    for i in 0..st.active.len() {
        let e = &st.active[i];
        if e.in_flight || e.handshake_state != Outcome::Ok || within(e.last_probed, COOLDOWN_MS) {
            continue;
        }
        // Newest credential first (smallest age since handshake).
        let better = match best {
            None => true,
            Some(j) => age_ms(e.last_handshaked) < age_ms(st.active[j].last_handshaked),
        };
        if better {
            best = Some(i);
        }
    }
    let i = best?;
    st.active[i].in_flight = true;
    Some(st.active[i])
}

fn record_handshake(st: &mut MideaState, sn: &[u8; 14], outcome: Outcome) {
    if let Some(e) = st.active.iter_mut().find(|e| &e.sn == sn) {
        e.in_flight = false;
        e.handshake_state = outcome;
        if outcome == Outcome::Ok {
            e.last_handshaked = Some(stamp());
        }
    }
}

/// Record a probe result, then retire the device: out of the active table and into
/// the 30-min cooldown so it is not reprocessed.
fn record_probe(st: &mut MideaState, sn: &[u8; 14], _outcome: Outcome) {
    if let Some(pos) = st.active.iter().position(|e| &e.sn == sn) {
        st.active.swap_remove(pos);
    }
    prune_cooldown(st);
    if st.cooldown.is_full() {
        st.cooldown.swap_remove(0);
    }
    let _ = st.cooldown.push((*sn, stamp()));
}

/// Log the whole device table — one line per active device with its timers/state.
fn log_table(st: &MideaState) {
    ulogf!("mtable: active={} cooldown={}\r\n", st.active.len(), st.cooldown.len());
    for e in &st.active {
        ulogf!(
            "  addr={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} sn={} last_seen_ms={} \
             last_hs_ms={} hs={} last_probe_ms={} probe={}{}\r\n",
            e.addr[5], e.addr[4], e.addr[3], e.addr[2], e.addr[1], e.addr[0],
            sn_string(&e.sn),
            age_ms(e.last_seen), age_ms(e.last_handshaked), e.handshake_state,
            age_ms(e.last_probed), e.last_probed_state,
            if e.in_flight { " *inflight" } else { "" },
        );
    }
}

// ── Tasks ─────────────────────────────────────────────────────────────────────

/// Discovery: every [`SCAN_PERIOD_MS`], log the table, then hold the radio for a
/// [`SCAN_WINDOW_MS`] scan and fold every matching Midea appliance into it.
#[embassy_executor::task]
pub async fn scan_task() -> ! {
    loop {
        {
            let st = STATE.lock().await;
            log_table(&st);
        }
        let found = {
            let mut rng = RADIO.lock().await;
            scan_midea(&mut rng).await
        };
        {
            let mut st = STATE.lock().await;
            for c in &found {
                upsert(&mut st, c);
            }
            evict_stale(&mut st);
            ulogf!("mscan: matched={} active={}\r\n", found.len(), st.active.len());
        }
        Timer::after_millis(SCAN_PERIOD_MS).await;
    }
}

/// Handshake worker: connect to a credential-less device and run C1→C2→C3.
#[embassy_executor::task]
pub async fn handshake_task() -> ! {
    loop {
        let Some(e) = ({
            let mut st = STATE.lock().await;
            pick_for_handshake(&mut st)
        }) else {
            Timer::after_millis(IDLE_POLL_MS).await;
            continue;
        };
        let outcome = {
            let mut rng = RADIO.lock().await;
            do_handshake(&mut rng, &e).await
        };
        let mut st = STATE.lock().await;
        record_handshake(&mut st, &e.sn, outcome);
    }
}

/// Probe worker pool: connect to the freshest credentialed-but-unprobed device,
/// read its status, record the result, and retire it to cooldown. Four run as a
/// work queue (serialized on the radio mutex).
#[embassy_executor::task(pool_size = 4)]
pub async fn probe_task() -> ! {
    loop {
        let Some(e) = ({
            let mut st = STATE.lock().await;
            pick_for_probe(&mut st)
        }) else {
            Timer::after_millis(IDLE_POLL_MS).await;
            continue;
        };
        let outcome = {
            let mut rng = RADIO.lock().await;
            do_probe(&mut rng, &e).await
        };
        let mut st = STATE.lock().await;
        record_probe(&mut st, &e.sn, outcome);
    }
}

/// Spawnable LED task — the state-colour indicator (`crate::led::LED` signal).
#[embassy_executor::task]
pub async fn led_task(mut leds: Pwm) -> ! {
    drive_indicator(&mut leds).await
}

// ── Midea protocol (moved from gatt.rs) ──────────────────────────────────────

/// Connection events to wait for a handshake reply notification, how many times
/// to resend a step whose reply never arrives (the appliance drops the first
/// frame of each step — midea-ble-go `session.go`), how long to passively listen
/// for status per device, and the cap on Midea targets handled per round.
const HS_REPLY_EVENTS: u32 = 60;
const HS_RETRIES: u32 = 4;

/// Running counters for the per-device summary line.
#[derive(Default)]
struct MideaStats {
    writes: u32, // ATT writes we sent (handshake frames)
    notifs: u32, // notifications received on FFA2
    status: u32, // decrypted 0xC0 status frames
}

/// Format the 14-byte ASCII short serial (printable characters only) for logging.
fn sn_string(sn: &[u8; 14]) -> heapless::String<14> {
    let mut s = heapless::String::new();
    for &b in sn {
        if (0x20..=0x7E).contains(&b) {
            let _ = s.push(b as char);
        }
    }
    s
}

/// Run the Midea control-channel handshake over the live link and return the
/// session state on success. Derives the rootKey from the advert (serial +
/// address), completes the ECDH session; all key material comes from the hardware
/// TRNG. Emits a detailed timing / packet trace for tuning.
async fn midea_handshake(
    conn: &mut Conn,
    prof: &device::midea::gatt::Profile,
    cand: &Candidate,
    st: &mut MideaStats,
) -> Option<device::midea::handshake::Handshake> {
    use device::midea::{crypto, handshake::{Handshake, Recv}, rng::HwRng};

    let sn = cand.sn?;
    let ad = crypto::advertis_data(&sn, &cand.addr);
    let mut rng = HwRng::new();
    // Client open-id: a 6-byte identifier the app would supply; zeros work here.
    let mut hs = Handshake::new(&ad, [0u8; 6], &mut rng)?;
    let t_start = Instant::now();
    ulogf!("  midea: state=c1 sn={} w={:04X} n={:04X} rootKey-derived (interval {}us, budget {} ev)\r\n",
        sn_string(&sn), prof.write_h, prof.notify_h, CONN_INTERVAL as u32 * 1250, HS_REPLY_EVENTS);

    let mut out = [0u8; ATT_MTU_MAX];

    // c1: rebuilt each attempt (new seq/nonce), as the device ignores the first.
    let mut c1_len = None;
    for attempt in 1..=HS_RETRIES {
        let f = hs.build_c1(&mut rng)?;
        let t0 = Instant::now();
        st.writes += 1;
        led::blink(led::RED, 1, 60, 60); // flash red on each handshake write
        if let Some(n) =
            att_write_await_notify(conn, prof.write_h, &f, prof.notify_h, HS_REPLY_EVENTS, &mut out).await
        {
            st.notifs += 1;
            led::blink(led::BLUE, 1, 40, 40); // flash blue on notification
            ulogf!("  midea[c1]: reply attempt={} in {}ms len={}\r\n",
                attempt, (Instant::now() - t0).as_millis(), n);
            c1_len = Some(n);
            break;
        }
        ulogf!("  midea[c1]: attempt={} no reply after {}ms\r\n",
            attempt, (Instant::now() - t0).as_millis());
    }
    let n = c1_len.or_else(|| { ulogf!("  midea: FAIL state=c1 (no reply)\r\n"); None })?;
    if let Some(Recv::C1(r)) = hs.on_recv(&out[..n]) {
        ulogf!("  midea: c1 ack result={}\r\n", r);
    }

    // c2: same frame on retry (a fresh c2 rotates the device's ephemeral key).
    ulogf!("  midea: state=c2\r\n");
    let c2 = hs.build_c2(&mut rng)?;
    let n = resend_await(conn, prof, &c2, &mut out, "c2", st).await
        .or_else(|| { ulogf!("  midea: FAIL state=c2 (no reply)\r\n"); None })?;
    let peer = match hs.on_recv(&out[..n]) {
        Some(Recv::C2(p)) => p,
        _ => { ulogf!("  midea: FAIL state=c2 (reply not a public key)\r\n"); return None }
    };
    let t_ecdh = Instant::now();
    hs.complete_c2(&peer, &mut rng)
        .or_else(|| { ulogf!("  midea: FAIL state=c2 (ECDH/session derivation)\r\n"); None })?;
    ulogf!("  midea: sessionKey established (ECDH {}ms)\r\n", (Instant::now() - t_ecdh).as_millis());

    // c3: our public key + sessionKey-encrypted advertisData, rootKey-wrapped.
    ulogf!("  midea: state=c3\r\n");
    let c3 = hs.build_c3(&mut rng)?;
    let n = resend_await(conn, prof, &c3, &mut out, "c3", st).await
        .or_else(|| { ulogf!("  midea: FAIL state=c3 (no reply)\r\n"); None })?;
    match hs.on_recv(&out[..n]) {
        Some(Recv::C3(r)) if r != 0 => ulogf!(
            "  midea: handshake complete (c3 result={}, {}ms total, tx={} rx={})\r\n",
            r, (Instant::now() - t_start).as_millis(), st.writes, st.notifs),
        Some(Recv::C3(r)) => { ulogf!("  midea: FAIL state=c3 (rejected result={})\r\n", r); return None }
        _ => { ulogf!("  midea: FAIL state=c3 (unexpected reply)\r\n"); return None }
    }
    Some(hs)
}

/// Resend one already-built handshake frame up to [`HS_RETRIES`] times, awaiting a
/// reply notification each time; logs attempt/latency and counts packets.
async fn resend_await(
    conn: &mut Conn,
    prof: &device::midea::gatt::Profile,
    frame: &[u8],
    out: &mut [u8],
    phase: &str,
    st: &mut MideaStats,
) -> Option<usize> {
    for attempt in 1..=HS_RETRIES {
        let t0 = Instant::now();
        st.writes += 1;
        led::blink(led::RED, 1, 60, 60); // flash red on each handshake write
        if let Some(n) =
            att_write_await_notify(conn, prof.write_h, frame, prof.notify_h, HS_REPLY_EVENTS, out).await
        {
            st.notifs += 1;
            led::blink(led::BLUE, 1, 40, 40); // flash blue on notification
            ulogf!("  midea[{}]: reply attempt={} in {}ms len={}\r\n",
                phase, attempt, (Instant::now() - t0).as_millis(), n);
            return Some(n);
        }
        ulogf!("  midea[{}]: attempt={} no reply after {}ms\r\n",
            phase, attempt, (Instant::now() - t0).as_millis());
    }
    None
}

/// Passively listen for `secs` seconds after the handshake, decrypting status
/// notifications pushed on FFA2 with the session key. No GATT writes are issued
/// here — the link is kept alive with empty PDUs only, and each decrypted 0xC0
/// status is logged with the device serial.
async fn midea_listen(
    conn: &mut Conn,
    prof: &device::midea::gatt::Profile,
    hs: &device::midea::handshake::Handshake,
    sn: &heapless::String<14>,
    secs: u64,
    st: &mut MideaStats,
) {
    use device::midea::{control, handshake::Recv};

    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut asm = Reasm::new();
    let mut owed: Option<([u8; 5], usize)> = None;
    let mut miss = 0u32;
    ulogf!("  midea: state=listen sn={} for {}s (passive, no writes)\r\n", sn, secs);

    while Instant::now() < deadline {
        let tx_len = match &owed {
            Some((b, n)) => stage_att(conn, &b[..*n]),
            None => stage_empty(conn),
        };
        let Some(rx) = conn_event(conn, tx_len).await else {
            miss += 1;
            if miss >= MAX_CONSEC_MISS {
                ulogf!("  midea: link lost during listen\r\n");
                break;
            }
            continue;
        };
        miss = 0;
        let (new_data, acked) = update_flow(conn, &rx);
        if acked {
            owed = None;
        }
        if !new_data || rx.len == 0 {
            continue;
        }
        let buf = unsafe { &*RX_BUF.0.get() };
        let payload = &buf[2..2 + rx.len as usize];
        match rx.llid {
            0b11 => handle_ll_control(payload),
            0b10 | 0b01 => {
                if !asm.push(rx.llid, payload) {
                    continue;
                }
                if asm.cid == 0x0004 {
                    let frame = asm.frame();
                    if frame.len() >= 3
                        && matches!(frame[0], ATT_HANDLE_VALUE_NTF | ATT_HANDLE_VALUE_IND)
                        && u16::from_le_bytes([frame[1], frame[2]]) == prof.notify_h
                    {
                        st.notifs += 1;
                        led::blink(led::BLUE, 1, 40, 40); // flash blue on notification
                        // The notification value is the Midea conn frame (AA 55…).
                        if let Some(Recv::Biz(body)) = hs.on_recv(&frame[3..])
                            && let Some(s) = control::parse_status_frame(&body)
                        {
                            st.status += 1;
                            ulogf!(
                                "  midea[{}] status: power={} mode={} temp={}.{}C fan={} swing[{}{}]\r\n",
                                sn, s.run_status, control::mode_name(s.mode),
                                s.temp_set / 10, s.temp_set % 10, control::wind_name(s.wind_speed),
                                if s.swing_ud { "V" } else { "" }, if s.swing_lr { "H" } else { "" }
                            );
                        }
                    } else if !log_notification(frame) {
                        decoder::protocol::l2cap::att::Att.decode(frame);
                        if let Some(r) = peer_att_reply(frame[0]) {
                            owed = Some(r);
                        }
                    }
                }
                asm.clear();
            }
            _ => {}
        }
    }
}

// ── Radio operations (each runs while its task holds the RADIO mutex) ──────────

/// Target-serial filter: starts with `2` and contains "AC".
fn sn_matches(sn: &[u8; 14]) -> bool {
    sn[0] == b'2' && sn.windows(2).any(|w| w == b"AC")
}

/// One scan window: sweep the advertising channels for [`SCAN_WINDOW_MS`], return
/// the matching Midea appliances (deduped by SN), and log the non-matching SNs.
async fn scan_midea(rng: &mut Rng) -> heapless::Vec<Candidate, ACTIVE_MAX> {
    configure_ble();
    let r = pac::RADIO;
    let mut found: heapless::Vec<Candidate, ACTIVE_MAX> = heapless::Vec::new();
    let mut others: heapless::Vec<[u8; 14], 32> = heapless::Vec::new();
    let end = Instant::now() + Duration::from_millis(SCAN_WINDOW_MS);
    while Instant::now() < end {
        for &(ch_idx, freq) in ADV_CHANNELS.iter() {
            ensure_disabled();
            r.frequency().write(|w| {
                w.set_frequency(freq);
                w.set_map(vals::Map::Default);
            });
            r.datawhiteiv().write(|w| w.set_datawhiteiv(ch_idx));
            r.packetptr().write_value(RX_BUF.0.get() as u32);
            r.events_end().write_value(0);
            r.events_crcok().write_value(0);
            r.events_address().write_value(0);
            r.events_disabled().write_value(0);
            r.shorts().write(|w| {
                w.set_rxready_start(true);
                w.set_address_rssistart(true);
            });
            r.tasks_rxen().write_value(1);

            let deadline = Instant::now() + Duration::from_millis(SURVEY_DWELL_MS);
            while Instant::now() < deadline {
                if r.events_end().read() != 0 {
                    r.events_end().write_value(0);
                    let crc_ok = r.events_crcok().read() != 0;
                    let rssi = -(r.rssisample().read().rssisample() as i16);
                    r.events_crcok().write_value(0);
                    r.events_address().write_value(0);
                    if crc_ok {
                        let buf = unsafe { &*RX_BUF.0.get() };
                        let pdu_type = buf[0] & 0x0F;
                        let len = buf[1] as usize;
                        if matches!(pdu_type, 0x00 | 0x01) && len >= 6 {
                            let addr = [buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
                            if let Some(sn) = parse_midea_sn(&buf[8..2 + len]) {
                                if sn_matches(&sn) {
                                    if !found.iter().any(|c| c.sn == Some(sn)) {
                                        let _ = found.push(Candidate {
                                            addr,
                                            addr_random: (buf[0] >> 6) & 1 == 1,
                                            rssi,
                                            sn: Some(sn),
                                        });
                                    }
                                } else if !others.iter().any(|o| o == &sn) {
                                    let _ = others.push(sn);
                                    ulogf!("mscan: other sn={} (filtered)\r\n", sn_string(&sn));
                                }
                            }
                        }
                    }
                    r.tasks_start().write_value(1);
                }
                Timer::after_micros(200).await;
                rng.stir(r.rssisample().read().rssisample() as u32);
            }
            r.shorts().write(|_w| {});
            r.tasks_disable().write_value(1);
            while r.events_disabled().read() == 0 {}
            r.events_disabled().write_value(0);
        }
    }
    found
}

/// Open a connection to `e` and walk to its Midea control profile. Returns the live
/// connection + profile, or `None` (radio left DISABLED) on any failure.
async fn open(rng: &mut Rng, e: &DeviceEntry) -> Option<(Conn, device::midea::gatt::Profile)> {
    CONN_AA.store(pick_access_address(rng), Ordering::Relaxed);
    pick_conn_params(rng);
    randomize_our_addr(rng);
    let cand = Candidate { addr: e.addr, addr_random: e.addr_random, rssi: 0, sn: Some(e.sn) };
    let mut cstat = ConnectStats::default();
    let mut conn = match try_connect(&cand, &mut cstat).await {
        Some(c) => c,
        None => {
            ulogf!("  connect failed (target={} connectable={})\r\n", cstat.target, cstat.connectable);
            ensure_disabled();
            configure_ble();
            return None;
        }
    };
    configure_conn_radio();
    // Pick FFA1/FFA2 out of the generic GATT walk via its per-characteristic callback.
    let mut write_h: Option<u16> = None;
    let mut notify_h: Option<u16> = None;
    enumerate(&mut conn, |vh, uuid| match device::midea::gatt::role(uuid) {
        Some(device::midea::gatt::Role::Write) => write_h = Some(vh),
        Some(device::midea::gatt::Role::Notify) => notify_h = Some(vh),
        _ => {}
    })
    .await;
    match (conn.ev_addr, write_h, notify_h) {
        (a, Some(write_h), Some(notify_h)) if a != 0 => {
            Some((conn, device::midea::gatt::Profile { write_h, notify_h }))
        }
        _ => {
            ulogf!("  no control profile (FFA1/FFA2 absent)\r\n");
            close(&mut conn).await;
            None
        }
    }
}

/// Tear the link down and leave the radio ready for the next holder.
async fn close(conn: &mut Conn) {
    if conn.ev_addr != 0 {
        terminate(conn).await;
    }
    ensure_disabled();
    configure_ble();
}

/// Connect + C1→C2→C3 handshake. Logs timing; returns the credential outcome.
async fn do_handshake(rng: &mut Rng, e: &DeviceEntry) -> Outcome {
    let sns = sn_string(&e.sn);
    let t0 = Instant::now();
    ulogf!("mhs: sn={} connecting\r\n", sns);
    let Some((mut conn, prof)) = open(rng, e).await else {
        ulogf!("mhs: sn={} FAIL (no link)\r\n", sns);
        return Outcome::Failed;
    };
    let cand = Candidate { addr: e.addr, addr_random: e.addr_random, rssi: 0, sn: Some(e.sn) };
    let mut stats = MideaStats::default();
    let ok = midea_handshake(&mut conn, &prof, &cand, &mut stats).await.is_some();
    ulogf!(
        "mhs: sn={} {} in {}ms (tx={} rx={})\r\n",
        sns, if ok { "credential OK" } else { "FAIL" },
        (Instant::now() - t0).as_millis(), stats.writes, stats.notifs
    );
    close(&mut conn).await;
    if ok { Outcome::Ok } else { Outcome::Failed }
}

/// Connect + handshake + status read (midea-ble-go `probe`). Logs the result.
async fn do_probe(rng: &mut Rng, e: &DeviceEntry) -> Outcome {
    let sns = sn_string(&e.sn);
    let t0 = Instant::now();
    ulogf!("mprobe: sn={} connecting\r\n", sns);
    let Some((mut conn, prof)) = open(rng, e).await else {
        ulogf!("mprobe: sn={} FAIL (no link)\r\n", sns);
        return Outcome::Failed;
    };
    let cand = Candidate { addr: e.addr, addr_random: e.addr_random, rssi: 0, sn: Some(e.sn) };
    let mut stats = MideaStats::default();
    let outcome = if let Some(hs) = midea_handshake(&mut conn, &prof, &cand, &mut stats).await {
        midea_listen(&mut conn, &prof, &hs, &sns, MIDEA_PROBE_SECS, &mut stats).await;
        ulogf!("mprobe: sn={} OK status={} in {}ms\r\n", sns, stats.status, (Instant::now() - t0).as_millis());
        Outcome::Ok
    } else {
        ulogf!("mprobe: sn={} FAIL (handshake) in {}ms\r\n", sns, (Instant::now() - t0).as_millis());
        Outcome::Failed
    };
    close(&mut conn).await;
    outcome
}
