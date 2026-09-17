//! BLE no-secret reconnaissance mode.
//!
//! Recon identifies undirected connectable `ADV_IND` advertisers, connects as a GATT central,
//! enumerates their complete primary-service database, and tests each readable,
//! writable, or subscribable characteristic without pairing or a pre-shared
//! secret. The radio is time-divided between devices by the loop in
//! [`gatt_recon`].

use core::cell::UnsafeCell;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;
use embassy_time::{Duration, Instant, Timer};

use super::ModeRef;
use crate::central::{ADV_CHANNELS, Candidate, Conn, RX_BUF, SURVEY_DWELL_MS, terminate};
use crate::hal::radio::{configure_ble_with_maxlen, ensure_disabled, wait_disabled};
use crate::{Rng, led};

const TABLE_MAX: usize = 128;
pub(crate) const SCAN_MAX: usize = 64;
const ADV_FLASH_MS: u64 = 250;

fn name_starts_with_ignore_case(name: &[u8], prefix: &[u8]) -> bool {
    name.len() >= prefix.len()
        && name[..prefix.len()]
            .iter()
            .zip(prefix)
            .all(|(&a, &b)| a.eq_ignore_ascii_case(&b))
}

pub(super) fn ignored_name_class(name: &[u8]) -> Option<&'static str> {
    if name_starts_with_ignore_case(name, b"Xperia") {
        Some("xperia")
    } else if name_starts_with_ignore_case(name, b"Mac") {
        Some("mac")
    } else {
        None
    }
}

struct ReconParams {
    scan_window_ms: u64,
    rssi_floor: i16,
    cooldown_ms: u64,
}

/// Active no-secret reconnaissance settings.
const PARAMS: ReconParams = ReconParams {
    scan_window_ms: 600,
    rssi_floor: -85,
    cooldown_ms: 3 * 60 * 1000,
};

fn stamp() -> NonZeroU64 {
    NonZeroU64::new(Instant::now().as_millis() + 1).unwrap()
}

fn age_ms(t: Option<NonZeroU64>) -> i64 {
    match t {
        Some(t) => stamp().get().saturating_sub(t.get()) as i64,
        None => -1,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeState {
    Seen,
    Probed,
    ProbeFailed,
}

impl core::fmt::Display for ProbeState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Seen => "seen",
            Self::Probed => "probed",
            Self::ProbeFailed => "probe_failed",
        })
    }
}

#[derive(Clone, Copy)]
struct DeviceEntry {
    addr: [u8; 6],
    addr_random: bool,
    rssi: i16,
    last_seen: Option<NonZeroU64>,
    last_probed: Option<NonZeroU64>,
    probe_state: ProbeState,
}

type Table = heapless::Vec<DeviceEntry, TABLE_MAX>;

struct TableCell(UnsafeCell<Table>);
unsafe impl Sync for TableCell {}
static TABLE: ModeRef<TableCell> = ModeRef::new();

#[derive(Clone, Copy)]
struct Recent {
    addr: [u8; 6],
    until: NonZeroU64,
}

type RecentRing = heapless::Vec<Recent, TABLE_MAX>;

fn in_cooldown(recent: &RecentRing, addr: &[u8; 6]) -> bool {
    let now = Instant::now().as_millis();
    recent
        .iter()
        .any(|r| &r.addr == addr && r.until.get() > now)
}

fn mark_recent(recent: &mut RecentRing, addr: [u8; 6], duration_ms: u64) {
    let until = NonZeroU64::new(Instant::now().as_millis() + duration_ms + 1).unwrap();
    if let Some(item) = recent.iter_mut().find(|r| r.addr == addr) {
        item.until = until;
        return;
    }
    if recent.is_full()
        && let Some(index) = (0..recent.len()).min_by_key(|&i| recent[i].until.get())
    {
        recent.swap_remove(index);
    }
    let _ = recent.push(Recent { addr, until });
}

fn refresh_seen(table: &mut Table, found: &[Candidate]) {
    for candidate in found {
        if let Some(entry) = table.iter_mut().find(|e| e.addr == candidate.addr) {
            entry.rssi = entry.rssi.max(candidate.rssi);
            entry.last_seen = Some(stamp());
        }
    }
}

fn track(table: &mut Table, candidate: &Candidate, state: ProbeState) {
    if let Some(entry) = table.iter_mut().find(|e| e.addr == candidate.addr) {
        entry.rssi = entry.rssi.max(candidate.rssi);
        entry.last_seen = Some(stamp());
        entry.last_probed = Some(stamp());
        entry.probe_state = state;
        return;
    }
    if table.is_full()
        && let Some(index) = (0..table.len()).max_by_key(|&i| age_ms(table[i].last_seen))
    {
        table.swap_remove(index);
    }
    let _ = table.push(DeviceEntry {
        addr: candidate.addr,
        addr_random: candidate.addr_random,
        rssi: candidate.rssi,
        last_seen: Some(stamp()),
        last_probed: Some(stamp()),
        probe_state: state,
    });
}

fn pick_candidate(found: &[Candidate], recent: &RecentRing) -> Option<usize> {
    found
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            candidate.rssi >= PARAMS.rssi_floor && !in_cooldown(recent, &candidate.addr)
        })
        .max_by_key(|(_, candidate)| candidate.rssi)
        .map(|(index, _)| index)
}

fn log_captured(adv_seen: u32, filtered: u32, found: &[Candidate], entries: usize) {
    ulogf!(
        "rscan: captured adv={} filtered={} candidates={} entries={} mode=no_secret_gatt\r\n",
        adv_seen,
        filtered,
        found.len(),
        entries
    );
}

/// Scan all three advertising channels for connectable legacy advertisements.
/// Advertised local names matching the built-in local-device filter are skipped;
/// peers without a usable local name proceed to the targeted GATT name pass.
async fn scan(rng: &mut Rng) -> (heapless::Vec<Candidate, SCAN_MAX>, u32, u32) {
    configure_ble_with_maxlen(254);
    let radio = pac::RADIO;
    let mut found: heapless::Vec<Candidate, SCAN_MAX> = heapless::Vec::new();
    let mut advertisements = 0u32;
    let mut filtered = 0u32;
    let mut last_flash: Option<Instant> = None;
    let end = Instant::now() + Duration::from_millis(PARAMS.scan_window_ms);

    while Instant::now() < end {
        for &(channel_index, frequency) in ADV_CHANNELS.iter() {
            ensure_disabled();
            radio.frequency().write(|w| {
                w.set_frequency(frequency);
                w.set_map(vals::Map::Default);
            });
            radio
                .datawhiteiv()
                .write(|w| w.set_datawhiteiv(channel_index));
            radio.packetptr().write_value(RX_BUF.0.get() as u32);
            radio.events_end().write_value(0);
            radio.events_crcok().write_value(0);
            radio.events_address().write_value(0);
            radio.events_disabled().write_value(0);
            radio.shorts().write(|w| {
                w.set_rxready_start(true);
                w.set_address_rssistart(true);
            });
            radio.tasks_rxen().write_value(1);

            let dwell_end = Instant::now() + Duration::from_millis(SURVEY_DWELL_MS);
            while Instant::now() < dwell_end {
                if radio.events_end().read() != 0 {
                    radio.events_end().write_value(0);
                    let crc_ok = radio.events_crcok().read() != 0;
                    let rssi = -(radio.rssisample().read().rssisample() as i16);
                    radio.events_crcok().write_value(0);
                    radio.events_address().write_value(0);
                    if crc_ok {
                        advertisements += 1;
                        let now = Instant::now();
                        if last_flash.is_none_or(|t| {
                            now.saturating_duration_since(t).as_millis() >= ADV_FLASH_MS
                        }) {
                            flash(led::WHITE, 1);
                            last_flash = Some(now);
                        }
                        let packet = unsafe { &*RX_BUF.0.get() };
                        let pdu_type = packet[0] & 0x0F;
                        let length = packet[1] as usize;
                        // ADV_IND is the undirected connectable legacy packet.
                        // Its payload may contain the full 31-byte advertising
                        // data area in addition to AdvA, so the PDU length can
                        // be as high as 37 bytes.
                        if pdu_type == 0x00 && (6..=37).contains(&length) {
                            let addr = [
                                packet[2], packet[3], packet[4], packet[5], packet[6], packet[7],
                            ];
                            let random = (packet[0] >> 6) & 1 == 1;
                            let ad = &packet[8..2 + length];
                            if crate::blacklist::adv_name(ad)
                                .and_then(ignored_name_class)
                                .is_some()
                            {
                                filtered += 1;
                                radio.tasks_start().write_value(1);
                                continue;
                            }
                            if let Some(candidate) = found.iter_mut().find(|c| c.addr == addr) {
                                candidate.rssi = candidate.rssi.max(rssi);
                            } else {
                                let _ = found.push(Candidate {
                                    addr,
                                    addr_random: random,
                                    rssi,
                                    interest: None,
                                    cap: None,
                                });
                            }
                        }
                    }
                    radio.tasks_start().write_value(1);
                }
                Timer::after_micros(200).await;
                rng.stir(radio.rssisample().read().rssisample() as u32);
            }
            radio.shorts().write(|_| {});
            radio.tasks_disable().write_value(1);
            let _ = wait_disabled();
            radio.events_disabled().write_value(0);
        }
    }
    (found, advertisements, filtered)
}

#[derive(Clone, Copy)]
enum Phase {
    Idle = 0,
    Scan = 1,
    Enumerate = 2,
    Handshake = 3,
    Listen = 4,
}

static PHASE: ModeRef<core::sync::atomic::AtomicU8> = ModeRef::new();

pub struct Storage {
    table: TableCell,
    phase: core::sync::atomic::AtomicU8,
}

impl Storage {
    pub const fn new() -> Self {
        Self {
            table: TableCell(UnsafeCell::new(heapless::Vec::new())),
            phase: core::sync::atomic::AtomicU8::new(0),
        }
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}

/// # Safety
/// Must be called once before the recon task starts.
pub unsafe fn bind_storage(storage: &'static Storage) {
    unsafe {
        TABLE.bind(&storage.table);
        PHASE.bind(&storage.phase);
    }
}

impl Phase {
    fn colour(self) -> led::Rgb {
        match self {
            Self::Idle => led::OFF,
            Self::Scan => led::GREEN,
            Self::Enumerate => led::BLUE,
            Self::Handshake => led::MAGENTA,
            Self::Listen => led::CYAN,
        }
    }
}

fn set_phase(phase: Phase) {
    PHASE.store(phase as u8, Ordering::Relaxed);
    led::solid(phase.colour());
}

pub(super) fn flash(colour: led::Rgb, count: u16) {
    let base = match PHASE.load(Ordering::Relaxed) {
        1 => Phase::Scan,
        2 => Phase::Enumerate,
        3 => Phase::Handshake,
        4 => Phase::Listen,
        _ => Phase::Idle,
    };
    led::blink_then(colour, base.colour(), count, 60, 60);
}

/// Tear down a link and restore the advertising-radio configuration.
pub(super) async fn close(conn: &mut Conn) {
    if conn.is_active() {
        terminate(conn).await;
    }
    ensure_disabled();
    configure_ble_with_maxlen(254);
}

pub async fn run() -> ! {
    gatt_recon::run().await
}

mod gatt_probe;
mod gatt_recon;
