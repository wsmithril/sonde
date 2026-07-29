//! BLE advertising sniffing.
//!
//! Phase 2 of each scanner cycle: dwell on the three primary advertising
//! channels (37/38/39, LE 1M), capture each received PDU, and follow any BLE-5
//! extended-advertising AuxPtr into the secondary data channels (`AUX_ADV_IND` /
//! `AUX_CHAIN_IND`).
//!
//! Capture and decode run concurrently in the mode's `run`: [`scan`] copies each
//! packet into [`RX_QUEUE`] and immediately re-arms the radio, while the consumer
//! branch drains the queue through the build's sink while the radio listens again.

use core::cell::UnsafeCell;
use core::fmt::Write as _; // `write!` into a LogStr when rendering the header to a sink
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_futures::join::join;
use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Instant, Timer};

use super::{Ctx, Mode};
use crate::hal::csa2;
use crate::hal::hash::fnv1a;
use crate::hal::radio::{
    arm_rxen_after, data_ch_freq, disable_silent, disarm_rxen, ensure_disabled, set_access_address,
    set_pcnf0, set_pcnf0_coded, use_fast_ramp_up, ADV_AA, ADV_CRC_INIT,
};
use crate::led::{OFF, OnBoardLed, Pwm, RED, Rgb};
use crate::{decoder, Rng, SyncBuf};

// ── BLE advertising constants ─────────────────────────────────────────────────

// (channel index, frequency offset from 2400 MHz)
const ADV_CHANNELS: [(u8, u8); 3] = [(37, 2), (38, 26), (39, 80)];

// 40 ms per channel × 3 channels — covers a full fast advertising interval
// (20–100 ms) + advDelay. The receiver stays armed across the whole dwell, so
// this is airtime: every packet that lands on the channel during it is captured.
const ADV_TOTAL_MS: u64 = 120;

// Derived — per-channel base window.
const ADV_DWELL_MS: u64 = ADV_TOTAL_MS / 3;

// Random 0..ADV_DWELL_JITTER_MS ms added to each channel's dwell, and the channel
// visit order is reshuffled every cycle. Both break the aliasing between our fixed
// scan cadence and an advertiser's periodic interval, so we don't systematically
// land in the gaps between advertising events.
const ADV_DWELL_JITTER_MS: u32 = 20;

// Primary-channel EVENTS_END poll granularity. Kept small (vs the old 1 ms) so an
// ADV_EXT_IND is noticed within ~150 µs of airing — short enough that its aux,
// which can follow only ~300 µs later (T_MAFS), is still reachable. Each poll
// still yields to the executor, so the USB logger keeps running.
//
// This bounds how long a completed packet sits in RX_BUF before we copy it out,
// not how much of the air we hear — END_START re-arms in hardware. The next
// packet begins overwriting that buffer ~40 µs after its own preamble, so a late
// poll costs a torn snapshot (counted as `torn=`), not a missed reception.
const PRIMARY_POLL_US: u64 = 150;


// ── Extended-advertising AuxPtr following ─────────────────────────────────────
// When an ADV_EXT_IND carries an AuxPtr, we schedule an RX window near the aux
// packet's predicted air time, catch it, then chain onto any further AuxPtr
// (AUX_CHAIN_IND).
//
// Timing is anchored to an *absolute* captured timestamp. The AuxPtr offset is
// measured from the start of the packet that carried it (the ADV_EXT_IND, or the
// previous aux for chain hops). The scan loop records `Instant::now()` the moment
// EVENTS_END fires and derives that packet's air-start (t_end − air duration);
// `follow_aux` then opens RX at `air_start + offset − AUX_OPEN_LEAD_US` via
// `Timer::at`. Scheduling against that absolute anchor keeps the window fixed to
// the air, so whatever work runs between reception and `follow_aux` leaves it
// where it is — which is what makes a short-offset aux reachable at all.
const AUX_MAX_HOPS: u8 = 4; // bound the AUX_CHAIN_IND chain length
const AUX_OPEN_LEAD_US: u32 = 300; // open RX this long before the predicted air time (ramp + drift)
const AUX_RX_WINDOW_US: u32 = 2500; // total poll span around the target (covers drift + air time)
const AUX_RX_WINDOW_CODED_US: u32 = 8000; // Coded PHY airs ~8× slower; widen the window (bounded freeze)
const AUX_MAX_LEAD_US: u32 = 60_000; // skip absurdly-distant aux (keep scanner responsive)

// EasyDMA receive buffer for BLE advertising PDUs. Sized for the largest aux
// packet: AUX_ADV_IND AdvData can reach 255 bytes, plus the 2-byte PDU header.
static RX_BUF: SyncBuf<258> = SyncBuf::new();

/// Snapshot of the packet currently being processed, copied out of [`RX_BUF`].
///
/// The primary scan re-arms the receiver in hardware (`END_START`) the instant a
/// packet completes, so [`RX_BUF`] starts filling with the *next* packet — a
/// T_IFS follow-up begins overwriting it ~190 µs later — while we are still
/// reading this one. Everything downstream of the copy works from here, off the
/// DMA path. Static rather than a local so it stays out of the scan future.
static PKT_BUF: SyncBuf<258> = SyncBuf::new();

// ── Decode queue ──────────────────────────────────────────────────────────────
// Decoding and formatting a packet costs ~0.6 ms (≈100 µs per log line, of which
// the QSPI vendor lookup is ~0.3 ms), and in a busy environment that is ~15% of
// wall clock. Doing it between DISABLE and the next RXEN spends all of it with
// the receiver off. Instead the scan copies each packet into this queue and
// re-arms immediately; [`log_task`] drains the queue and does the decode while
// the radio is listening again.
//
// Depth 8 against a ~0.6 ms service time and a ~4 ms mean packet gap leaves the
// queue near-empty in steady state; it is sized to absorb the burst of one
// advertising event (the same payload on 37/38/39 within ~2 ms) plus the 5 ms
// tail of a large ext-adv decode.
const RX_QUEUE_DEPTH: usize = 8;

/// Where a queued packet was captured, and the metadata that only its capture
/// context knows.
pub enum RxSrc {
    /// One of the three primary advertising channels.
    Primary,
    /// A secondary (data) channel reached by following an AuxPtr. `adi` is the
    /// triggering ADV_EXT_IND's ADI, shown alongside the aux for correlation.
    Aux { phy: u8, adi: Option<u16> },
}

/// One captured PDU, copied out of [`RX_BUF`] so the radio can re-arm before it
/// is decoded.
pub struct RxPacket {
    /// Air-start of the packet. Every line logged for it carries this instant —
    /// see [`crate::with_log_stamp`].
    pub t_air: Instant,
    /// PDU header + payload, as received. Sized like [`RX_BUF`] because an
    /// AUX_ADV_IND payload can reach 255 bytes; primary PDUs use ~40 of it.
    pub data: [u8; 258],
    /// Valid bytes in `data`, header included.
    pub len: u16,
    pub rssi_dbm: i16,
    /// Repeat count from [`note_and_throttle`]; 0 for a first sighting.
    pub rpt: u32,
    /// Low 16 bits of the payload fingerprint.
    pub fp: u16,
    pub ch: u8,
    /// PDU type from the header, or 0xFF when `crc_ok` is false.
    pub pdu_type: u8,
    pub crc_ok: bool,
    pub src: RxSrc,
}

pub static RX_QUEUE: Channel<CriticalSectionRawMutex, RxPacket, RX_QUEUE_DEPTH> = Channel::new();

/// Copies the first `len` bytes of `bytes` into the decode queue.
///
/// A plain `fn`, which builds the packet on the stack and keeps it out of the
/// scan task's future. A full queue returns immediately and records a drop in the
/// stats, holding the capture path to a bounded cost.
#[allow(clippy::too_many_arguments)]
fn enqueue(
    bytes: &[u8],
    t_air: Instant,
    ch: u8,
    rssi_dbm: i16,
    crc_ok: bool,
    pdu_type: u8,
    len: usize,
    rpt: u32,
    fp: u16,
    src: RxSrc,
) {
    let len = len.min(bytes.len());
    let mut p = RxPacket {
        t_air,
        data: [0u8; 258],
        len: len as u16,
        rssi_dbm,
        rpt,
        fp,
        ch,
        pdu_type,
        crc_ok,
        src,
    };
    p.data[..len].copy_from_slice(&bytes[..len]);
    if RX_QUEUE.try_send(p).is_err() {
        stats_drop();
    }
}

/// Copies the just-completed PDU out of the DMA buffer into [`PKT_BUF`],
/// returning its total length (2-byte header included).
///
/// Called with the receiver already re-armed, so this is a race against the next
/// packet's DMA; the caller checks `EVENTS_ADDRESS` afterwards to see whether it
/// won. Only the bytes the header claims are copied — a legacy PDU is ~40 of the
/// 258, and the copy sits directly in that race.
fn snapshot_rx() -> usize {
    let src = unsafe { &*RX_BUF.0.get() };
    // 8-bit Length (BLE 5 / LFLEN=8). On a CRC failure this is whatever noise
    // landed in the header byte, hence the clamp.
    let n = (2 + src[1] as usize).min(src.len());
    unsafe { (&mut *PKT_BUF.0.get())[..n].copy_from_slice(&src[..n]) };
    n
}

// ── Repeat throttling ─────────────────────────────────────────────────────────
// Static beacons re-advertise the same payload endlessly. We remember recently
// seen payload hashes and collapse identical frames so genuinely new devices are
// not buried in the log. Matching is payload-hash first (not address first), so a
// device rotating its resolvable private address while re-advertising the same
// payload collapses to one entry instead of inflating the log with a "new" line
// per rotation.
const THROTTLE_SLOTS: usize = 48;
const REPEAT_NOTICE_EVERY: u32 = 16; // still print one line per this many repeats

#[derive(Clone, Copy)]
struct SeenEntry {
    used: bool,
    addr: [u8; 6],
    hash: u32,
    count: u32,
}

struct SeenCache(UnsafeCell<[SeenEntry; THROTTLE_SLOTS]>);
unsafe impl Sync for SeenCache {}
static SEEN: SeenCache = SeenCache(UnsafeCell::new(
    [SeenEntry { used: false, addr: [0; 6], hash: 0, count: 0 }; THROTTLE_SLOTS],
));

enum Repeat {
    New,
    Again(u32),
}

/// Records a received (addr, payload) and reports whether it repeats a frame we
/// already logged. Matching is payload-hash first, so a device rotating its
/// resolvable private address but re-advertising an identical payload collapses
/// to one tracked entry (the address is refreshed on each match). A changed
/// payload from a known address is the interesting event and counts as new; a
/// fresh device evicts the least-chatty tracked entry.
fn note_and_throttle(addr: [u8; 6], payload: &[u8]) -> Repeat {
    let hash = fnv1a(payload);
    let cache = unsafe { &mut *SEEN.0.get() };
    // Pass 1: identical payload from any address → repeat. Refresh the address so
    // the entry keeps tracking the device across RPA rotation.
    for e in cache.iter_mut() {
        if e.used && e.hash == hash {
            e.addr = addr;
            e.count = e.count.saturating_add(1);
            return Repeat::Again(e.count);
        }
    }
    // Pass 2: known address, changed payload → the interesting event, treat as new.
    for e in cache.iter_mut() {
        if e.used && e.addr == addr {
            e.hash = hash;
            e.count = 0;
            return Repeat::New;
        }
    }
    // Insert: reuse a free slot, else evict the lowest-count entry so frequent
    // repeaters stay tracked (and suppressed).
    let mut victim = 0usize;
    let mut lowest = u32::MAX;
    for (i, e) in cache.iter().enumerate() {
        if !e.used {
            victim = i;
            break;
        }
        if e.count < lowest {
            lowest = e.count;
            victim = i;
        }
    }
    cache[victim] = SeenEntry { used: true, addr, hash, count: 0 };
    Repeat::New
}

// ── Periodic statistics ───────────────────────────────────────────────────────
// A summary line every STATS_CYCLES scan cycles gives an at-a-glance health
// check (reception rate, environment busyness) without scraping the packet log.
const STATS_CYCLES: u32 = 20;

struct Stats {
    cycles: u32,
    pkts: u32,
    crc_ok: u32,
    suppressed: u32,
    /// Packets discarded because [`RX_QUEUE`] was full — the decoder falling
    /// behind the radio.
    dropped: u32,
    /// Snapshots abandoned because the next packet's DMA reached [`RX_BUF`]
    /// first — the radio out-running the copy, not the decoder.
    torn: u32,
    /// CRC-failed frames that passed the [`salvage`] plausibility gate and were
    /// logged anyway.
    salvaged: u32,
    strongest: i16,
}

struct StatsCell(UnsafeCell<Stats>);
unsafe impl Sync for StatsCell {}
static STATS: StatsCell = StatsCell(UnsafeCell::new(Stats {
    cycles: 0,
    pkts: 0,
    crc_ok: 0,
    suppressed: 0,
    dropped: 0,
    torn: 0,
    salvaged: 0,
    strongest: -128,
}));

/// Packets captured since boot, for [`crate::sniff_led`].
///
/// [`Stats`] is reset at the end of every window, so it cannot be differenced by
/// an observer on its own schedule. This one only ever counts up; the indicator
/// samples it and takes the difference itself.
pub static PKT_TOTAL: AtomicU32 = AtomicU32::new(0);

/// The [`crate::RADIO_RECOVERED`] reading at the last window emit, so `stats_tick`
/// can report the per-window count as a difference. `RADIO_RECOVERED` only counts
/// up (the LED and the log both want the all-time total intact), so the window
/// figure is this subtraction rather than a field reset with the rest of [`Stats`].
static RECOVERED_PREV: AtomicU32 = AtomicU32::new(0);

fn stats_record(crc_ok: bool, rssi_dbm: i16, suppressed: bool) {
    let s = unsafe { &mut *STATS.0.get() };
    PKT_TOTAL.fetch_add(1, Ordering::Relaxed);
    s.pkts += 1;
    if crc_ok {
        s.crc_ok += 1;
    }
    if suppressed {
        s.suppressed += 1;
    }
    if rssi_dbm > s.strongest {
        s.strongest = rssi_dbm;
    }
}

fn stats_drop() {
    let s = unsafe { &mut *STATS.0.get() };
    crate::ERR_TOTAL.fetch_add(1, Ordering::Relaxed);
    s.dropped += 1;
}

fn stats_torn() {
    let s = unsafe { &mut *STATS.0.get() };
    crate::ERR_TOTAL.fetch_add(1, Ordering::Relaxed);
    s.torn += 1;
}

fn stats_salvage() {
    let s = unsafe { &mut *STATS.0.get() };
    s.salvaged += 1;
}

/// Called once per scan cycle; emits and resets the window every STATS_CYCLES.
fn stats_tick() {
    let s = unsafe { &mut *STATS.0.get() };
    s.cycles += 1;
    if s.cycles < STATS_CYCLES {
        return;
    }
    let pct = (s.crc_ok * 100).checked_div(s.pkts).unwrap_or(0);
    // radio_stuck recoveries since the last window: RADIO_RECOVERED is monotonic,
    // so difference it here rather than resetting a Stats field.
    let recovered_now = crate::RADIO_RECOVERED.load(Ordering::Relaxed);
    let recovered = recovered_now.wrapping_sub(RECOVERED_PREV.swap(recovered_now, Ordering::Relaxed));
    // Every field describes the window that is about to be reset.
    ulogf!(
        "[STAT] cycles={} pkts={} crc_ok={}% strongest={}dBm suppressed={} dropped={} torn={} salvaged={} recovered={}\r\n",
        s.cycles, s.pkts, pct, s.strongest, s.suppressed, s.dropped, s.torn, s.salvaged, recovered
    );
    *s = Stats {
        cycles: 0, pkts: 0, crc_ok: 0, suppressed: 0, dropped: 0, torn: 0, salvaged: 0,
        strongest: -128,
    };
}

// ── Extended-advertising AuxPtr following ─────────────────────────────────────

/// Follows an AuxPtr chain discovered in an ADV_EXT_IND: retunes to each pointed
/// data channel, holds RX open (wide window) until the aux packet arrives or the
/// window elapses, queues it for decoding, and continues onto any further AuxPtr
/// (AUX_CHAIN_IND) up to `AUX_MAX_HOPS`. Runs inline in the scan, so it preempts
/// the channel walk and delays the next primary scan until it returns.
/// Only 1M/2M PHY is followed (Coded is logged and skipped). The RADIO is left
/// reconfigured for 1M primary reception on return.
///
/// The `aux_*` diagnostics go straight to [`crate::log_send`], so each carries
/// the instant the chain reached that state and lands in the log ahead of the
/// packet lines it describes.
///
/// `t_ref` is the air-start `Instant` of the packet that carried `first`'s
/// AuxPtr (the ADV_EXT_IND); the aux offset is measured from there. Each caught
/// aux updates `t_ref` to its own air-start so a chained AUX_CHAIN_IND offset is
/// scheduled from the correct anchor.
async fn follow_aux(first: decoder::AuxPtr, adi: Option<u16>, mut t_ref: Instant) {
    let r = pac::RADIO;
    let mut next = Some(first);
    let mut hops = 0u8;
    // First SyncInfo seen in this aux chain → follow the periodic train after the
    // chain ends: (params, air-start anchor of the carrying packet, its PHY).
    let mut sync_seen: Option<(decoder::SyncInfo, Instant, u8)> = None;

    while let Some(aux) = next {
        if hops >= AUX_MAX_HOPS { ulog!("[ERR] aux_max_hops\r\n"); break; }
        hops += 1;

        // PHY: 1M, 2M, and Coded (LE Long Range) are all followed.
        let (mode, plen, coded) = match aux.phy {
            0 => (vals::Mode::Ble1mbit, vals::Plen::_8bit, false),
            1 => (vals::Mode::Ble2mbit, vals::Plen::_16bit, false),
            2 => (vals::Mode::BleLr125kbit, vals::Plen::LongRange, true),
            _ => { ulog!("[ERR] aux_bad_phy\r\n"); break; }
        };
        let freq = match data_ch_freq(aux.chan) {
            Some(f) => f,
            None => { ulog!("[ERR] aux_bad_ch\r\n"); break; }
        };
        // A distant aux would stall the primary scan for tens of ms; skip it.
        if aux.offset_us > AUX_MAX_LEAD_US { ulog!("[ERR] aux_offset_far\r\n"); break; }

        // Schedule against the absolute air-start reference: the aux airs at
        // `t_ref + offset`. Open RX AUX_OPEN_LEAD_US before that (radio ramp +
        // drift). Because the target is absolute, any latency between receiving
        // the trigger and arriving here does not shift the window; if we are
        // already past `open_at`, Timer::at returns immediately.
        let target = t_ref + Duration::from_micros(aux.offset_us as u64);
        let open_at = target - Duration::from_micros(AUX_OPEN_LEAD_US as u64);

        // Everything below is register traffic with no dependence on the clock,
        // so it runs *before* the wait. Done after, it landed inside the window
        // instead of ahead of it: `Timer::at` yields, the decode task runs for
        // however long it runs, and only then does the retune happen — which is
        // why aux hit rate fell off with offset (59% under 500 µs, 30% at 2-4 ms)
        // while short offsets, which never yield at all, did best. TASKS_RXEN is
        // the one thing that has to happen at the deadline, so it is the only
        // thing left after it.
        //
        // Safe across the yield because the scan task is the sole owner of the
        // RADIO in this mode; the decode and log tasks never touch it.
        //
        // Silent, not `ensure_disabled`: the primary scan is still in RX
        // here — the channel-visit teardown is skipped on the path that reaches
        // an aux chase — so a running radio is the expected state, not a fault.
        disable_silent();
        r.mode().write(|w| w.set_mode(mode));
        if coded { set_pcnf0_coded(); } else { set_pcnf0(plen); }
        r.frequency().write(|w| { w.set_frequency(freq); w.set_map(vals::Map::Default); });
        r.datawhiteiv().write(|w| w.set_datawhiteiv(aux.chan));
        r.packetptr().write_value(RX_BUF.0.get() as u32);

        r.events_end().write_value(0);
        r.events_crcok().write_value(0);
        r.events_address().write_value(0);
        r.events_disabled().write_value(0);
        r.shorts().write(|w| {
            w.set_rxready_start(true);
            w.set_address_rssistart(true);
        });

        // Fire RXEN in hardware at open_at: a TIMER1 compare routed to TASKS_RXEN
        // over PPI opens RX at the deadline regardless of when this task next runs.
        // The await below only aligns the poll loop with the window — the receiver
        // ramps on the compare whether or not we have resumed yet, so the executor
        // latency that pushed short RX opens past the aux's air time is gone.
        let now = Instant::now();
        let lead_us = open_at.saturating_duration_since(now).as_micros() as u32;
        arm_rxen_after(lead_us);
        if open_at > now {
            Timer::at(open_at).await;
        }

        // Short scheduled window: RX is now open near the predicted air time.
        // Poll EVENTS_END in ~200 µs steps (keeps the USB logger running) for a
        // fixed span covering clock drift + air time.
        let mut got = false;
        let mut t_aux_end = Instant::now();
        let window_us = if coded { AUX_RX_WINDOW_CODED_US } else { AUX_RX_WINDOW_US };
        for _ in 0..(window_us / 200 + 1) {
            if r.events_end().read() != 0 {
                r.events_end().write_value(0);
                t_aux_end = Instant::now();
                got = true;
                break;
            }
            Timer::after_micros(200).await;
        }

        disable_silent();
        disarm_rxen();

        if !got { ulog!("[ERR] aux_miss\r\n"); break; }

        let crc_ok   = r.events_crcok().read() != 0;
        let rssi_dbm = -(r.rssisample().read().rssisample() as i16);
        let buf      = unsafe { &*RX_BUF.0.get() };
        let length   = buf[1]; // ext-adv length is a full 8-bit field (LFLEN=8)
        let payload_len = (length as usize).min(buf.len().saturating_sub(2));

        // Air-start of the aux just received. Uncoded: (10 + len) bytes × per-byte
        // time (8 µs on 1M, 4 µs on 2M). Coded: a fixed FEC1 preamble/AA/CI/TERM1
        // overhead (~400 µs, always S=8) plus (5 + len) header+CRC bytes at the
        // S=8 payload rate (64 µs/byte) — approximate, since the payload may be
        // S=2; good enough for log ordering and the chain re-anchor.
        let air_us: u64 = match aux.phy {
            1 => (10 + length as u64) * 4,
            2 => 400 + (5 + length as u64) * 64,
            _ => (10 + length as u64) * 8,
        };
        let t_air = t_aux_end - Duration::from_micros(air_us);

        if !crc_ok {
            enqueue(buf, t_air, aux.chan, rssi_dbm, false, 0xFF, 2 + payload_len, 0, 0,
                RxSrc::Aux { phy: aux.phy, adi });
            break;
        }

        // Walk the aux extended header here, on the capture path, for the ADI and
        // any further AuxPtr: both decide what this loop does next. The printed
        // decode of the same header happens in log_task.
        let ext = decoder::parse_ext_hdr(&buf[2..2 + payload_len]);

        // A periodic advertiser announces its train via SyncInfo in the
        // AUX_ADV_IND; remember the first one to follow once the aux chain ends.
        if sync_seen.is_none()
            && let Some(si) = ext.sync
        {
            sync_seen = Some((si, t_air, aux.phy));
        }

        enqueue(buf, t_air, aux.chan, rssi_dbm, true, 0x07, 2 + payload_len, 0, 0,
            RxSrc::Aux { phy: aux.phy, adi });

        // ADI collision check: an aux channel is shared, so the packet we caught
        // may belong to a different advertiser. If the trigger's ADI and the aux's
        // ADI both exist and differ, this is not our advertising set — log and stop.
        if let (Some(want), Some(got_adi)) = (adi, ext.adi)
            && want != got_adi
        {
            ulogf!("[ERR] aux_adi_mismatch want=0x{:03X} got=0x{:03X}\r\n", want, got_adi);
            break;
        }

        // Re-anchor for a possible AUX_CHAIN_IND: its offset is measured from the
        // start of the aux we just received.
        t_ref = t_air;

        next = ext.aux; // chain onto AUX_CHAIN_IND, if any
    }

    // Restore 1M primary reception for the next channel iteration.
    ensure_disabled();
    r.mode().write(|w| w.set_mode(vals::Mode::Ble1mbit));
    set_pcnf0(vals::Plen::_8bit);

    // If this aux announced a periodic train, follow it now (bounded). This
    // freezes the primary scan for its duration, hence the tight PSYNC_* caps.
    if let Some((si, t_anchor, sphy)) = sync_seen {
        follow_periodic(si, t_anchor, sphy).await;
    }
}

// ── Periodic advertising sync (folded into the aux follower) ───────────────────
//
// An AUX_ADV_IND from a periodic advertiser carries a SyncInfo giving the
// periodic Access Address, CRCInit, channel map, interval, and offset to the
// first AUX_SYNC_IND. Following it means retuning to the periodic AA, hopping the
// data channels by CSA#2 (keyed on the periodic AA + paEventCounter), and
// decoding each AUX_SYNC_IND (+ any chained AUX_CHAIN_IND) as an extended-adv
// PDU. The follow runs inline in `scan`, so it is bounded to a few events.
const PSYNC_MAX_EVENTS: u32 = 3; // stop after this many caught AUX_SYNC_IND
const PSYNC_MAX_MISS: u32 = 2; // stop after this many consecutive misses
const PSYNC_MAX_INTERVAL_US: u32 = 1_000_000; // skip trains slower than ~1 s
const PSYNC_MAX_LEAD_US: u32 = 120_000; // skip a first sync further out than this
const PSYNC_OPEN_LEAD_US: u32 = 400; // open RX this long before predicted air time
const PSYNC_RX_WINDOW_US: u32 = 3000; // poll span per periodic event (uncoded)

/// One captured extended-advertising PDU. The AA/CRCInit in effect at capture
/// time is the caller's responsibility (aux uses ADV_AA; periodic uses the
/// periodic AA), so this only carries the decoded framing back.
struct ExtCapture {
    t_air: Instant,
    crc_ok: bool,
    payload_len: usize,
    rssi_dbm: i16,
}

/// Schedule and capture a single ext-adv PDU: wait until `open_at`, retune to
/// `(chan, freq, phy)`, open RX, and poll EVENTS_END for up to `window_us`.
/// Returns `None` on a miss. Used by the periodic follower for both AUX_SYNC_IND
/// and its AUX_CHAIN_IND; `follow_aux` keeps its own inline copy (the verified
/// path) to avoid perturbing it.
async fn capture_ext_pdu(
    chan: u8,
    freq: u8,
    phy: u8,
    open_at: Instant,
    window_us: u32,
) -> Option<ExtCapture> {
    let r = pac::RADIO;
    if open_at > Instant::now() {
        Timer::at(open_at).await;
    }

    let (mode, coded) = match phy {
        1 => (vals::Mode::Ble2mbit, false),
        2 => (vals::Mode::BleLr125kbit, true),
        _ => (vals::Mode::Ble1mbit, false),
    };
    ensure_disabled();
    r.mode().write(|w| w.set_mode(mode));
    if coded {
        set_pcnf0_coded();
    } else {
        set_pcnf0(if phy == 1 { vals::Plen::_16bit } else { vals::Plen::_8bit });
    }
    r.frequency().write(|w| { w.set_frequency(freq); w.set_map(vals::Map::Default); });
    r.datawhiteiv().write(|w| w.set_datawhiteiv(chan));
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

    let mut got = false;
    let mut t_end = Instant::now();
    for _ in 0..(window_us / 200 + 1) {
        if r.events_end().read() != 0 {
            r.events_end().write_value(0);
            t_end = Instant::now();
            got = true;
            break;
        }
        Timer::after_micros(200).await;
    }
    disable_silent();

    if !got {
        return None;
    }

    let crc_ok = r.events_crcok().read() != 0;
    let rssi_dbm = -(r.rssisample().read().rssisample() as i16);
    let buf = unsafe { &*RX_BUF.0.get() };
    let length = buf[1];
    let payload_len = (length as usize).min(buf.len().saturating_sub(2));
    let air_us: u64 = match phy {
        1 => (10 + length as u64) * 4,
        2 => 400 + (5 + length as u64) * 64,
        _ => (10 + length as u64) * 8,
    };
    Some(ExtCapture { t_air: t_end - Duration::from_micros(air_us), crc_ok, payload_len, rssi_dbm })
}

/// Follow a periodic advertising train announced by `si`, caught in an
/// AUX_ADV_IND whose air-start was `t_anchor` on PHY `phy`. Bounded by `PSYNC_*`.
async fn follow_periodic(si: decoder::SyncInfo, t_anchor: Instant, phy: u8) {
    let r = pac::RADIO;

    let interval_us = si.interval_125us as u32 * 1250;
    // Guard: unschedulable offset, or a train too slow/far to camp on.
    if si.offset_us == 0
        || si.offset_us > PSYNC_MAX_LEAD_US
        || interval_us == 0
        || interval_us > PSYNC_MAX_INTERVAL_US
    {
        ulogf!("[ERR] psync_skip aa=0x{:08X} off={}us int={}us\r\n", si.aa, si.offset_us, interval_us);
        return;
    }
    if phy > 2 {
        ulog!("[ERR] psync_bad_phy\r\n");
        return;
    }

    let coded = phy == 2;
    let window_us = if coded { AUX_RX_WINDOW_CODED_US } else { PSYNC_RX_WINDOW_US };
    let chan_id = csa2::chan_id(si.aa);
    let mut counter = si.event_counter;
    // First AUX_SYNC_IND airs at the anchor + SyncInfo offset.
    let mut t_ref = t_anchor + Duration::from_micros(si.offset_us as u64);
    let mut events = 0u32;
    let mut miss = 0u32;

    // Override the radio to the periodic AA/CRCInit for the whole follow.
    ensure_disabled();
    set_access_address(si.aa);
    r.crcinit().write(|w| w.set_crcinit(si.crc_init));

    while events < PSYNC_MAX_EVENTS && miss < PSYNC_MAX_MISS {
        let (ch, freq) = match csa2::channel(counter, chan_id, &si.chm) {
            Some(cf) => cf,
            None => { ulog!("[ERR] psync_no_chan\r\n"); break; }
        };
        let open_at = t_ref - Duration::from_micros(PSYNC_OPEN_LEAD_US as u64);
        let cap = capture_ext_pdu(ch, freq, phy, open_at, window_us).await;

        let Some(cap) = cap else {
            miss += 1;
            counter = counter.wrapping_add(1);
            t_ref += Duration::from_micros(interval_us as u64);
            continue;
        };

        let plen = cap.payload_len;
        enqueue(unsafe { &*RX_BUF.0.get() }, cap.t_air, ch, cap.rssi_dbm, cap.crc_ok,
            if cap.crc_ok { 0x07 } else { 0xFF }, 2 + plen, 0, 0,
            RxSrc::Aux { phy, adi: None });

        if !cap.crc_ok {
            miss += 1;
            counter = counter.wrapping_add(1);
            t_ref += Duration::from_micros(interval_us as u64);
            continue;
        }

        events += 1;
        miss = 0;

        // Follow any AUX_CHAIN_IND for this event. Chained PDUs ride the same
        // periodic AA/CRCInit (still configured), so only the schedule/channel
        // changes; the offset is measured from each preceding packet's air-start.
        let mut chain_next = decoder::parse_ext_hdr(&unsafe { &*RX_BUF.0.get() }[2..2 + plen]).aux;
        let mut chain_ref = cap.t_air;
        let mut chops = 0u8;
        while let Some(cx) = chain_next {
            if chops >= AUX_MAX_HOPS || cx.phy > 2 {
                break;
            }
            chops += 1;
            let cfreq = match data_ch_freq(cx.chan) {
                Some(f) => f,
                None => break,
            };
            let cwin = if cx.phy == 2 { AUX_RX_WINDOW_CODED_US } else { PSYNC_RX_WINDOW_US };
            let copen = chain_ref + Duration::from_micros(cx.offset_us as u64)
                - Duration::from_micros(PSYNC_OPEN_LEAD_US as u64);
            let Some(cc) = capture_ext_pdu(cx.chan, cfreq, cx.phy, copen, cwin).await else {
                break;
            };
            let cplen = cc.payload_len;
            enqueue(unsafe { &*RX_BUF.0.get() }, cc.t_air, cx.chan, cc.rssi_dbm, cc.crc_ok,
                if cc.crc_ok { 0x07 } else { 0xFF }, 2 + cplen, 0, 0,
                RxSrc::Aux { phy: cx.phy, adi: None });
            if !cc.crc_ok {
                break;
            }
            chain_ref = cc.t_air;
            chain_next = decoder::parse_ext_hdr(&unsafe { &*RX_BUF.0.get() }[2..2 + cplen]).aux;
        }

        counter = counter.wrapping_add(1);
        t_ref = cap.t_air + Duration::from_micros(interval_us as u64);
    }

    let ms_x100 = si.interval_125us as u32 * 125;
    ulogf!("psync aa=0x{:08X} evt0={} interval={}.{:02}ms events={} miss={}\r\n",
        si.aa, si.event_counter, ms_x100 / 100, ms_x100 % 100, events, miss);

    // Restore advertising AA/CRCInit + 1M primary for the scanner.
    ensure_disabled();
    set_access_address(ADV_AA);
    r.crcinit().write(|w| w.set_crcinit(ADV_CRC_INIT));
    r.mode().write(|w| w.set_mode(vals::Mode::Ble1mbit));
    set_pcnf0(vals::Plen::_8bit);
}

// ── Phase 2: BLE advertising packet detection ─────────────────────────────────
//
// 3 channels × (ADV_DWELL_MS + jitter). EVENTS_END is polled every PRIMARY_POLL_US,
// so active channels return within ~150 µs of a packet landing (and we timestamp
// it for aux scheduling); quiet channels burn the full (jittered) dwell window.
// Any AuxPtr is followed inline before moving on.
pub async fn scan(rng: &mut Rng) {
    // ── Polling-based BLE advertising packet detection ────────────────────────
    // Interrupt-driven reception (ISR) was not working — neither #[no_mangle]
    // nor bind_interrupts! correctly wired the RADIO vector on this embassy-nrf
    // build without the nrf-pac rt feature. Polling EVENTS_END every
    // PRIMARY_POLL_US is simpler and equally effective: the radio listens
    // continuously, and we catch each received packet within ~150 µs of arrival
    // (fast enough that a closely-following aux is still reachable). Each Timer
    // yield keeps the USB logger task running so serial output stays live.
    //
    // Fisher–Yates shuffle so channel visit order (and thus each channel's
    // sampling phase) varies every cycle.
    let mut order = ADV_CHANNELS;
    for i in (1..order.len()).rev() {
        let j = rng.below((i + 1) as u32) as usize;
        order.swap(i, j);
    }
    // Whether any valid packet was received this cycle; drives the idle LED-off.
    for &(ch_idx, freq) in order.iter() {
        let r = pac::RADIO;

        ensure_disabled();
        r.frequency().write(|w| { w.set_frequency(freq); w.set_map(vals::Map::Default); });
        r.datawhiteiv().write(|w| w.set_datawhiteiv(ch_idx));
        r.packetptr().write_value(RX_BUF.0.get() as u32);

        r.events_end().write_value(0);
        r.events_crcok().write_value(0);
        r.events_crcerror().write_value(0);
        r.events_address().write_value(0);
        r.events_sync().write_value(0);
        r.events_disabled().write_value(0);
        // RXREADY→START begins reception; ADDRESS→RSSISTART captures the signal
        // strength of a packet the moment its access address matches; END→START
        // re-arms the receiver in hardware the instant one completes.
        //
        // END_START is what makes the second half of a T_IFS exchange reachable.
        // A SCAN_REQ or CONNECT_IND airs exactly 150 µs after the ADV_IND it
        // answers, which is shorter than the software re-arm path — even from
        // RXIDLE, where there is no ramp to pay — so only the hardware short
        // gets the receiver back on air in time to hear it.
        r.shorts().write(|w| {
            w.set_rxready_start(true);
            w.set_address_rssistart(true);
            w.set_end_start(true);
        });
        r.tasks_rxen().write_value(1);

        let dwell = Duration::from_micros(
            (ADV_DWELL_MS + rng.below(ADV_DWELL_JITTER_MS) as u64) * 1000,
        );
        let deadline = Instant::now() + dwell;
        // Set when an AuxPtr was followed: the radio has been retuned and
        // reconfigured, so this channel visit is over.
        let mut left_channel = false;

        while Instant::now() < deadline {
            if r.events_end().read() == 0 {
                Timer::after_micros(PRIMARY_POLL_US).await;
                continue;
            }
            // ── A packet completed ───────────────────────────────────────────
            // The receiver is already listening again, so everything from here
            // races the next packet's DMA. Read the per-packet registers first
            // (ADDRESS→RSSISTART re-samples RSSI on the next address match),
            // then snapshot the buffer, then check whether we won the race.
            r.events_end().write_value(0);
            let t_end  = Instant::now();
            let crc_ok = r.events_crcok().read() != 0;
            r.events_crcok().write_value(0);
            r.events_crcerror().write_value(0);
            let rssi_dbm = -(r.rssisample().read().rssisample() as i16);

            r.events_address().write_value(0);
            let n = snapshot_rx();
            // A fresh address match during the copy means the next packet was
            // already writing into RX_BUF: the snapshot may be torn. (Not
            // airtight — if the match happened before the clear above we miss
            // it — but it catches the common case and keeps the cost visible in
            // the stats rather than silently corrupting a decode.)
            if r.events_address().read() != 0 {
                stats_torn();
                continue;
            }

            let buf = &unsafe { &*PKT_BUF.0.get() }[..n];
            // BLE 5 advertising PDU header Length is a full 8 bits. Masking it
            // to 6 (the BLE 4.0 field width) truncated every ADV_EXT_IND
            // payload over 63 bytes.
            let length   = buf[1];
            let pdu_type = if crc_ok { buf[0] & 0x0F } else { 0xFF };

            // ADV_EXT_IND carries no legacy AdvA at the payload start (its AdvA,
            // if present, lives in the extended header), so it has no address to
            // classify or throttle on here.
            let is_ext      = pdu_type == 0x07;
            // A CRC-failed reception has no trustworthy header: `length`, the
            // TxAdd bit and the six bytes that would be AdvA all come out of a
            // corrupted buffer. Reporting them produced a fabricated address —
            // and a confident "rand-rpa" / OUI classification of it — on every
            // bad packet, which is most of a busy capture.
            // `length` is the *claimed* PDU length from the header; `n` is how many
            // bytes were actually DMA'd. A torn/truncated reception can leave `n`
            // short (as little as the 2-byte header) while the length byte still
            // claims ≥6 — reading the 6-byte AdvA at buf[2..8] then indexes past the
            // buffer and panics. Require the buffer to actually hold the AdvA.
            let has_addr    = crc_ok && !is_ext && length >= 6 && n >= 8;
            let payload_len = (length as usize).min(buf.len().saturating_sub(2));

            // ── Repeat throttling ────────────────────────────────────────────
            // Collapse consecutive identical (addr,payload) frames. A repeat is
            // fully suppressed except every REPEAT_NOTICE_EVERY-th sighting, which
            // still prints one line (with rpt=N) so the device stays visible.
            // fp: low 16 bits of a fingerprint over the ADVERTISING DATA only — the
            // 6-byte AdvA is skipped, so it stays stable as a device rotates its RPA
            // (the address changes, the advertising content usually does not).
            // Hashing from buf[2] (which includes AdvA) would change every rotation
            // and defeat the whole point of the handle.
            let fp = if crc_ok && has_addr {
                let ad = if payload_len > 6 {
                    &buf[8..2 + payload_len] // AdvData: skip AdvA at buf[2..8]
                } else {
                    &buf[2..2 + payload_len] // no AdvData (e.g. DIRECT_IND) — hash what's there
                };
                fnv1a(ad) as u16
            } else {
                0
            };
            let repeat = if crc_ok && has_addr {
                let addr = [buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
                note_and_throttle(addr, &buf[2..2 + payload_len])
            } else {
                Repeat::New
            };
            let suppress = matches!(repeat, Repeat::Again(n) if n % REPEAT_NOTICE_EVERY != 0);
            stats_record(crc_ok, rssi_dbm, suppress);
            if suppress {
                continue; // skip the verbose log for this repeat
            }

            // ── AuxPtr extraction ────────────────────────────────────────────
            // The extended header is walked here, on the capture path: an aux
            // packet can air only ~300 µs after its ADV_EXT_IND, so the follow
            // decision has to be ready by the end of this iteration. log_task
            // walks the same header again for the printed fields.
            let ext = if crc_ok && is_ext && (length as usize) > 1 {
                decoder::parse_ext_hdr(&buf[2..2 + payload_len])
            } else {
                decoder::ExtInfo::default()
            };

            // Air-start of this packet: t_end − air, air = (10 + len) bytes ×
            // 8 µs (1M primary channel). Stamps its log lines, and anchors the
            // aux schedule below.
            let t_air = t_end - Duration::from_micros((10 + length as u64) * 8);

            let rpt = if let Repeat::Again(n) = repeat { n } else { 0 };
            enqueue(buf, t_air, ch_idx, rssi_dbm, crc_ok, pdu_type, 2 + payload_len,
                rpt, fp, RxSrc::Primary);

            // ── Follow AuxPtr to the secondary channel ───────────────────────
            // Runs inline: preempts the remaining channel walk and delays the
            // next primary scan until the aux chain completes. It retunes and
            // reconfigures the radio, so this channel visit ends here rather
            // than resuming a dwell whose receiver is now on a data channel.
            if let Some(aux) = ext.aux {
                let (aux, adi) = (aux, ext.adi);
                follow_aux(aux, adi, t_air).await;
                left_channel = true;
                break;
            }
        }

        if !left_channel {
            disable_silent();
        }
    }

    // One scan cycle complete — fold into the periodic stats summary.
    stats_tick();
}

// ── Decode and logging ────────────────────────────────────────────────────────

/// BLE advertising access address — the fixed AA for PCAP records of adverts.
pub const ADV_ACCESS_ADDR: u32 = 0x8E89_BED6;

/// A captured advert is a [`crate::mode::Frame`]: it decodes itself (full typed
/// decode, no field loss) for the console, and exposes its PCAP fields for SD.
impl crate::mode::Frame for RxPacket {
    fn t_air(&self) -> Instant {
        self.t_air
    }
    fn decode_to<S: crate::Sink>(&self, out: &mut S) {
        let d = Decoded { hdr: Header::parse(self), pkt: self };
        d.write_text_to(out);
    }
    fn ch(&self) -> u8 {
        self.ch
    }
    fn rssi(&self) -> i8 {
        self.rssi_dbm as i8
    }
    fn crc_ok(&self) -> bool {
        self.crc_ok
    }
    fn access_addr(&self) -> u32 {
        ADV_ACCESS_ADDR
    }
    fn payload(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

/// The typed, parsed header of an advertising packet — the common fields the
/// decode and log paths need, extracted once so consumers (a renderer, a JSON
/// exporter, a filter) read them instead of re-deriving. This is the phase-B
/// parsed result held in [`Decoded`]; per-vendor *body* fields are still rendered
/// as text for now (the long tail of field-typing lands incrementally).
pub struct Header {
    pub pdu_type: u8,
    /// On-air length field (payload length; `p.len - 2`).
    pub len: u16,
    pub ch: u8,
    pub rssi_dbm: i16,
    pub crc_ok: bool,
    /// TxAdd: true = random address, false = public.
    pub tx_random: bool,
    pub is_ext: bool,
    pub fp: u16,
    pub rpt: u32,
    /// Advertiser address in display order (MSB first) when the frame carried a
    /// usable one (CRC ok, not ext-adv, long enough); else `None`.
    pub addr: Option<[u8; 6]>,
}

impl Header {
    /// Parse the header fields from a captured packet — pure, no rendering.
    pub fn parse(p: &RxPacket) -> Self {
        let len = p.len.saturating_sub(2);
        let is_ext = p.pdu_type == 0x07;
        let tx_random = !p.data.is_empty() && (p.data[0] >> 6) & 1 != 0;
        let addr = if p.crc_ok && !is_ext && len >= 6 && p.len as usize >= 8 {
            let a = &p.data[2..8]; // on air LSB-first → store MSB-first for display
            Some([a[5], a[4], a[3], a[2], a[1], a[0]])
        } else {
            None
        };
        Header {
            pdu_type: p.pdu_type,
            len,
            ch: p.ch,
            rssi_dbm: p.rssi_dbm,
            crc_ok: p.crc_ok,
            tx_random,
            is_ext,
            fp: p.fp,
            rpt: p.rpt,
            addr,
        }
    }

    /// SIG name for this PDU type.
    pub fn name(&self) -> &'static str {
        pdu_name(self.pdu_type)
    }

    /// Address classification: "pub", or the random subtype from the top two bits
    /// of the MSB octet.
    pub fn addr_type(&self) -> &'static str {
        if !self.tx_random {
            return "pub";
        }
        match self.addr.map(|a| a[0] >> 6) {
            Some(0b11) => "rand-static",
            Some(0b01) => "rand-rpa",
            Some(0b00) => "rand-nonres",
            _ => "rand-rfu",
        }
    }
}

/// A captured advertising packet, its typed [`Header`], and its render entry point.
///
/// The parse/render seam: decoding produces a `Decoded` holding the parsed header,
/// and [`write_text_to`](Decoded::write_text_to) renders it to any
/// [`Sink`](crate::Sink). The body is still rendered by the existing decoders;
/// migrating them to read `hdr`/typed fields (while preserving the exact log text
/// the host analysis pipeline parses) is the remaining phase-B work.
pub struct Decoded<'a> {
    pub hdr: Header,
    pub pkt: &'a RxPacket,
}

impl Decoded<'_> {
    /// The parsed header — for consumers that inspect/filter/export without
    /// re-parsing (e.g. `if d.header().rssi_dbm > -60 { … }`).
    pub fn header(&self) -> &Header {
        &self.hdr
    }

    /// Render the decode of this packet to `sink`. Runs in the decode task, never
    /// on the radio path; the sink must not block (radio-first rule).
    pub fn write_text_to(&self, sink: &mut impl crate::Sink) {
        let _scope = decoder::SinkScope::new(sink);
        emit_packet(self.pkt, &self.hdr);
    }
}

fn emit_packet(p: &RxPacket, h: &Header) {
    match p.src {
        RxSrc::Primary => emit_primary(p, h),
        RxSrc::Aux { phy, adi } => emit_aux(p, phy, adi),
    }
}

/// Logs a packet caught on a primary advertising channel: header line, vendor
/// lookup, AdvData decode, hex dump.
/// SIG name for a primary-channel advertising PDU type (low nibble of header 0).
fn pdu_name(t: u8) -> &'static str {
    match t {
        0x00 => "ADV_IND",
        0x01 => "ADV_DIRECT_IND",
        0x02 => "ADV_NONCONN_IND",
        0x03 => "SCAN_REQ",
        0x04 => "SCAN_RSP",
        0x05 => "CONNECT_IND",
        0x06 => "ADV_SCAN_IND",
        0x07 => "ADV_EXT_IND",
        _ => "UNK",
    }
}

/// Decides whether a CRC-failed legacy advertising PDU is worth showing anyway,
/// returning its PDU type if so.
///
/// A CRC failure means at least one bit of the frame is wrong; it does not say
/// which, and in a capture that is a third CRC errors, throwing all of them away
/// discards a lot of readable traffic — a conn-follow run recovered a complete,
/// structurally valid `LL_VERSION_IND` from a frame the CRC rejected. So rather
/// than trust the CRC alone, check whether the frame is *self-consistent* in two
/// independent ways that random corruption would almost certainly break:
///
/// 1. **Header.** RFU bit 4 of the type octet is zero, the type is a legacy one,
///    and Length matches what the spec fixes or bounds for that type.
/// 2. **Payload.** The AD structures walk from the first length octet to exactly
///    the last byte of the payload, with no zero-length entry and no overrun.
///
/// Both holding means the corruption — if it is in this frame at all rather than
/// in the CRC itself — landed inside an AD value, where it is visible as odd data
/// rather than invisible as a wrong address. Frames that pass are logged with an
/// explicit marker and are deliberately kept out of the device table and the
/// repeat throttle; see the call site.
fn salvage(buf: &[u8]) -> Option<u8> {
    if buf.len() < 8 {
        return None;
    }
    if buf[0] & 0x10 != 0 {
        return None; // RFU bit set — not a well-formed header
    }
    let t = buf[0] & 0x0F;
    let length = buf[1] as usize;
    if length + 2 != buf.len() {
        return None;
    }
    let ok_len = match t {
        0x00 | 0x02 | 0x04 | 0x06 => (6..=37).contains(&length),
        0x01 | 0x03 => length == 12,
        0x05 => length == 34,
        _ => false, // ADV_EXT_IND has no fixed shape to check against
    };
    if !ok_len {
        return None;
    }
    // An all-zero or all-ones AdvA is a corrupted field, not a device.
    let a = &buf[2..8];
    if a.iter().all(|&b| b == 0x00) || a.iter().all(|&b| b == 0xFF) {
        return None;
    }
    // Directed/request PDUs are all address, with no AD structures to check, so
    // the header gate is all they get.
    if matches!(t, 0x01 | 0x03 | 0x05) {
        return Some(t);
    }
    // AD structures must tile the payload exactly.
    let mut i = 8;
    while i < buf.len() {
        let l = buf[i] as usize;
        if l == 0 {
            return None;
        }
        i += 1 + l;
    }
    if i == buf.len() {
        Some(t)
    } else {
        None
    }
}

fn emit_primary(p: &RxPacket, h: &Header) {
    let buf      = &p.data[..p.len as usize];
    let length   = p.len - 2; // the on-air length field, as captured
    let hdr0     = buf[0];
    let tx_add   = (hdr0 >> 6) & 1; // 1=random, 0=public
    let crc_ok   = p.crc_ok;
    let ch_idx   = p.ch;
    let rssi_dbm = p.rssi_dbm;

    // The header fields (name, address, classification, len, crc, …) are the
    // typed `Header` parsed in `Header::parse`; the header line is rendered from
    // it below. The locals above stay for the body/salvage decode that follows.
    let is_ext   = p.pdu_type == 0x07;

    // Where the hex dump at the bottom starts, as an offset into the payload
    // (`buf[2..]`), or `None` for no dump at all. Every decode path below narrows
    // it to whatever it could not account for; the default dumps everything,
    // which is what a PDU type with no decoder should get.
    let mut unparsed = Some(0usize);

    // ── Header line ──────────────────────────────────────────────────────────
    // Format: "TYPE ch=XX len=NN addr=AA:BB:CC:DD:EE:FF <type> crc=ok".
    // BLE address is transmitted LSB-first; reverse bytes for display.
    // <type> is the address classification (public, or the random subtype from
    // the top two bits of the MSB octet).
    if let Some(ad) = h.addr {
        let a = &buf[2..8]; // on-air LSB-first, for the RPA/vendor lookups below
        // Header line rendered from the typed `Header` and routed through the sink
        // (byte-identical to the previous `ulogf!` form).
        let mut line = decoder::LogStr::new();
        let _ = write!(line,
            "{} ch={} rssi={} len={} addr={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} {} fp={:04X} crc={}",
            h.name(), h.ch, h.rssi_dbm, h.len,
            ad[0], ad[1], ad[2], ad[3], ad[4], ad[5], h.addr_type(), h.fp,
            if h.crc_ok { "ok" } else { "err" });
        if h.rpt > 0 {
            let _ = write!(line, " rpt={}", h.rpt);
        }
        let _ = write!(line, "\r\n");
        decoder::emit(line);
        // RPA resolution (#8): a rand-rpa address is prand (3 MSB octets, top two
        // bits 0b01) + hash (3 LSB octets). With a matching IRK compiled in, the
        // rotating address resolves to a stable identity. Off unless built with
        // `resolve-identities`.
        #[cfg(feature = "resolve-identities")]
        if tx_add != 0 && a[5] >> 6 == 0b01 {
            let prand = [a[5], a[4], a[3]];
            let hash = [a[2], a[1], a[0]];
            for (irk, label) in crate::keys::IRKS {
                if crate::hal::crypto::ah(irk, &prand) == hash {
                    emitf!("  identity: {} (RPA resolved)\r\n", label);
                    break;
                }
            }
        }
        // Vendor lookup for public addresses: the top three octets are the IEEE
        // OUI. Emitted on its own line so a long org name never truncates the
        // header (both share the log line buffer).
        if tx_add == 0 {
            let prefix = (a[5] as u32) << 16 | (a[4] as u32) << 8 | a[3] as u32;
            // AdvA is LSB-first, so the 12 bits below the OUI — which name the
            // assignee inside a subdivided block — are the 4th display octet and
            // the high nibble of the 5th.
            let ext12 = (a[2] as u16) << 4 | (a[1] >> 4) as u16;
            if let Some(v) = decoder::oui_vendor(prefix, Some(ext12)) {
                emitf!("  vendor: {}\r\n", v);
            }
        }
    } else if h.crc_ok {
        let mut line = decoder::LogStr::new();
        let _ = write!(line, "{} ch={} rssi={} len={} {} crc=ok\r\n",
            h.name(), h.ch, h.rssi_dbm, h.len,
            if tx_add == 1 { "rand" } else { "pub" });
        decoder::emit(line);
    } else {
        // Channel and RSSI are measured by the radio and stand on their own;
        // everything else is whatever the corrupted buffer holds, so the received
        // length is reported as raw and nothing is decoded from it.
        //
        // Unless the frame survives the plausibility gate in `salvage` — a CRC
        // failure is one flipped bit somewhere, not necessarily in a field worth
        // discarding the whole frame over, and a third of a busy capture is CRC
        // errors.
        match salvage(buf) {
            Some(t) => {
                stats_salvage();
                let a = &buf[2..8];
                emitf!("CRC-ERR ch={} rssi={} rawlen={} crc=err salvaged={} \
                        addr?={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\r\n",
                    ch_idx, rssi_dbm, length, pdu_name(t),
                    a[5], a[4], a[3], a[2], a[1], a[0]);
                // Every field on the following lines is unverified: the trailing
                // `?` on `addr?` above and this marker are the only claim made
                // for them. Nothing here reaches the repeat throttle — a salvaged
                // address is for a human reading the log, not for state that has
                // to be defensible.
                emitf!("  (salvaged: header and AD structure both walk clean; \
                        CRC still failed — treat every field as unverified)\r\n");
                if matches!(t, 0x00 | 0x02 | 0x04 | 0x06) && length > 6 {
                    let adva = [buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
                    let ad = &buf[8..];
                    unparsed = tail(6, decoder::log_ad_structures(ad, Some(adva), false), ad.len());
                }
            }
            None => {
                // A frame that fails both the CRC and the plausibility gate has
                // no byte worth printing: the header line's channel and RSSI are
                // measured, the payload is noise. This is the single largest
                // source of log volume in a busy capture, so it stops here.
                emitf!("CRC-ERR ch={} rssi={} rawlen={} crc=err\r\n",
                    ch_idx, rssi_dbm, length);
                unparsed = None;
            }
        }
    }

    // ── AdvData / extended-header decode ─────────────────────────────────────
    // Garbage from a bad-CRC packet is not worth decoding.
    if crc_ok && length > 1 {
        if is_ext {
            // BLE 5 extended advertising: log the extended header fields, then
            // decode any trailing AdvData. The scan already took the AuxPtr out
            // of this same header and has followed it by now.
            //
            // The walk reports whole-payload success or nothing; unlike the AD
            // walk it cannot say *where* it gave up, because a malformed
            // extended header invalidates every offset derived from it.
            unparsed = if decoder::decode_ext_adv(&buf[2..]).ok { None } else { Some(0) };
        } else if matches!(p.pdu_type, 0x00 | 0x02 | 0x04 | 0x06) && length > 6 {
            // Legacy undirected adv / scan-response: AdvA[6] then AD structures.
            // Pass AdvA (buf[2..8], on-air LE) so the decoder can flag "mfg data
            // == own address".
            let adva = [buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
            let ad = &buf[8..];
            unparsed = tail(6, decoder::log_ad_structures(ad, Some(adva), true), ad.len());
        } else if matches!(p.pdu_type, 0x01 | 0x03) && length == 12 {
            // ADV_DIRECT_IND (AdvA, TargetA) and SCAN_REQ (ScanA, AdvA) carry two
            // addresses and nothing else. The header line already named the first
            // (buf[2..8]); name the second party here and mark the payload fully
            // accounted for. Left undecoded, this pair dumped its whole payload,
            // and the two types together were about half of all dumped bytes in a
            // busy capture.
            let b = &buf[8..14];
            // The RxAdd bit (header octet 0, bit 7) classifies this second
            // address the way TxAdd classifies the first.
            let rx_add = (hdr0 >> 7) & 1;
            let bt = if rx_add == 0 {
                "pub"
            } else {
                match b[5] >> 6 {
                    0b11 => "rand-static",
                    0b01 => "rand-rpa",
                    0b00 => "rand-nonres",
                    _    => "rand-rfu",
                }
            };
            let role = if p.pdu_type == 0x01 { "target" } else { "adv" };
            ulogf!("  {}={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} {}\r\n",
                role, b[5], b[4], b[3], b[2], b[1], b[0], bt);
            unparsed = None;
        } else if p.pdu_type == 0x05 && length == 34 {
            // CONNECT_IND: InitA[6] AdvA[6] LLData[22]. Sniff mode only decodes
            // the link setup (addresses + access address + connection params);
            // it never follows the connection — that is the dedicated conn-follow
            // boot mode ([`crate::mode::conn_follow`]).
            //
            // Gate the decode on the same plausibility check the follower applies
            // ([`decoder::ConnSpec::is_followable`]). A CRC that passes still lets
            // through a reception corrupted outside the checked fields, and a
            // CONNECT_IND cannot fail to parse — every 34-byte payload yields a
            // well-formed `ConnSpec`, often full of nonsense (79-second
            // intervals, hop 0). Without the gate those dominate the decoded
            // CONNECT_IND lines; with it an implausible one gets a single marker
            // and its raw bytes, not a page of fabricated link parameters.
            match decoder::parse_connect_ind(buf[0], &buf[2..]) {
                Some(spec) if spec.is_followable() => {
                    decoder::decode_connect_ind(buf[0], &buf[2..]);
                    unparsed = None;
                }
                _ => ulogf!("  [ERR] (implausible CONNECT_IND params — not decoded)\r\n"),
            }
        }
    }

    // ── Payload hex dump ─────────────────────────────────────────────────────
    // Only for what the decoders could not account for: a bad CRC, a PDU type
    // with no decoder, a truncated AD structure, an extended header claiming
    // more bytes than arrived. A packet that decoded cleanly has every byte of
    // it already named in the lines above, so the dump is pure duplication —
    // and it was half the bytes on the wire, which is what capped the capture
    // rate (DESIGN-NOTES §5). Where it still prints, it prints from the first
    // byte the decode could not place, because those bytes are the only record
    // of what actually arrived.
    if let Some(off) = unparsed {
        let end = (2 + 37).min(buf.len());
        if 2 + off < end {
            crate::hexdump(&buf[2 + off..end], off, 2);
        }
    }
}

/// The dump start for a walk that consumed `consumed` of `total` bytes beginning
/// at payload offset `base`, or `None` when it consumed all of them.
fn tail(base: usize, consumed: usize, total: usize) -> Option<usize> {
    if consumed >= total { None } else { Some(base + consumed) }
}

/// Logs a packet caught by following an AuxPtr onto a secondary channel.
fn emit_aux(p: &RxPacket, phy: u8, adi: Option<u16>) {
    let buf    = &p.data[..p.len as usize];
    let length = p.len - 2;

    if !p.crc_ok {
        emitf!("AUX_ADV_IND ch={} rssi={} len={} crc=err\r\n",
            p.ch, p.rssi_dbm, length);
        return;
    }

    // The ADI shown is the trigger's — the scan's collision check confirms the
    // aux matches it.
    match adi {
        Some(a) => emitf!("AUX_ADV_IND ch={} phy={} rssi={} len={} adi=0x{:03X} crc=ok\r\n",
            p.ch, if phy == 1 { "2M" } else { "1M" }, p.rssi_dbm, length, a),
        None => emitf!("AUX_ADV_IND ch={} phy={} rssi={} len={} crc=ok\r\n",
            p.ch, if phy == 1 { "2M" } else { "1M" }, p.rssi_dbm, length),
    }

    if !decoder::decode_ext_adv(&buf[2..]).ok {
        crate::hexdump(&buf[2..], 0, 2);
    }
}

// ── Mode ──────────────────────────────────────────────────────────────────────
//
// The BLE-sniff boot mode: a passive advertising scan across the primary channels
// with inline AuxPtr following, forever. `run` produces into [`RX_QUEUE`] and drains
// it through the build's [`super::CaptureSink`] (`sink_frame`); [`led_task`] shows
// capture rate/liveness on the onboard LED.

/// Carries the sink type `K` (a ZST via `PhantomData`); the mode holds no state —
/// entropy and the sink live in the static [`Ctx`].
pub struct BleSniff<K: super::CaptureSink>(PhantomData<K>);

impl<K: super::CaptureSink> BleSniff<K> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<K: super::CaptureSink> Default for BleSniff<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: super::CaptureSink> Mode for BleSniff<K> {
    type Sink = K;

    async fn init<F: core::future::Future<Output = ()>>(&mut self, _ctx: &'static Ctx<K>, setup: F) {
        // Build-specific plumbing first (USB: QSPI asset window + provisioning + LED;
        // headless: LED task) — the mode stays oblivious to which.
        setup.await;
        // Fast ramp-up is safe for an RX-only scan: no T_IFS turnaround for the
        // shorter ramp to miss.
        use_fast_ramp_up();
    }

    async fn led_control<L: OnBoardLed>(led: &mut L) -> ! {
        drive_led(led).await
    }

    async fn run(&mut self, ctx: &'static Ctx<K>) -> ! {
        ctx.sink().begin();
        // `rng` and `sink` come from separate cells, so the producer and consumer
        // can run concurrently without aliasing.
        let rng = ctx.rng();
        let sink = ctx.sink();

        let produce = async {
            loop {
                scan(rng).await;
            }
        };
        // Decode/format overlaps reception: the radio is listening again while
        // this drains the queue a packet at a time.
        let consume = async {
            loop {
                let p = RX_QUEUE.receive().await;
                sink.sink_frame(&p);
            }
        };
        join(produce, consume).await;
        // Both branches loop forever, so join never returns.
        unreachable!()
    }
}

/// Spawnable wrapper around [`drive_led`] — the concrete task a binary spawns
/// alongside `run` (a `#[task]` can't be a trait method).
#[embassy_executor::task]
pub async fn led_task(mut leds: Pwm) -> ! {
    drive_led(&mut leds).await
}

/// Sniff-mode LED indicator (calls the `led` primitives): dark at rest, a 1 ms
/// blink per packet in a colour that carries the capture rate (blue→cyan→green over
/// packets/s), and a red frame whenever [`crate::ERR_TOTAL`] moves. Reads two
/// monotonic counters on its own schedule, so the capture path pays nothing here
/// beyond a `fetch_add`. Shared by [`BleSniff::led_control`] and [`led_task`].
async fn drive_led<L: OnBoardLed>(led: &mut L) -> ! {
    /// Render period, and so the width of a blink and of a loss flash.
    const FRAME_MS: u64 = 1;
    /// Frames per rate sample (folded into the EWMA over a 50 ms window).
    const FRAMES_PER_SAMPLE: u32 = 50;
    /// Top of the scale, packets/s: blue at nothing, cyan at half, green at ≥.
    const RATE_MAX: u32 = 640;
    /// Green die's light against blue at equal duty, so hue alone carries rate.
    const LUM_G: u32 = 6;
    /// EWMA weight as a right shift: `new = old + (sample - old) >> SHIFT`.
    const EWMA_SHIFT: u32 = 4;

    let mut prev_pkts = PKT_TOTAL.load(Ordering::Relaxed);
    let mut prev_errs = crate::ERR_TOTAL.load(Ordering::Relaxed);
    // Seeded from the first sample, not zero, so the LED does not show the filter
    // climbing to the true rate on entry.
    let mut ewma_q8: Option<i32> = None;

    let mut window: u32 = 0;
    let mut frame: u32 = 0;
    let mut mix = OFF;
    let mut shown = OFF;

    led.set(shown);
    loop {
        Timer::after_millis(FRAME_MS).await;

        let pkts = PKT_TOTAL.load(Ordering::Relaxed);
        let arrived = pkts.wrapping_sub(prev_pkts);
        prev_pkts = pkts;
        window += arrived;

        frame += 1;
        let flash = if frame == FRAMES_PER_SAMPLE {
            frame = 0;
            let sample = (window * (1000 / (FRAME_MS as u32 * FRAMES_PER_SAMPLE))) as i32;
            window = 0;
            let e = match ewma_q8 {
                Some(e) => e + (((sample << 8) - e) >> EWMA_SHIFT),
                None => sample << 8,
            };
            ewma_q8 = Some(e);

            let errs = crate::ERR_TOTAL.load(Ordering::Relaxed);
            let moved = errs != prev_errs;
            prev_errs = errs;

            // Position along the fade: 0 blue, 256 cyan, 512 green.
            let rate = e.max(0) as u32 >> 8;
            let pos = (rate * 512 / RATE_MAX).min(512);
            // Blue at full drive sets the luminance budget; green claims `pos/512`
            // of it and blue the rest, each square-rooted back through the gamma
            // `Pwm::set` applies — 255² is the full-blue budget.
            let g = (65025 * pos / (512 * LUM_G)).isqrt() as u8;
            let b = (65025 * (512 - pos) / 512).isqrt() as u8;
            mix = Rgb::new(0, g, b);

            moved
        } else {
            false
        };

        // Light the frame a packet landed in; several inside one frame light it
        // once — the blink says the air is live, the colour the rate.
        let want = if flash {
            RED
        } else if arrived > 0 {
            mix
        } else {
            OFF
        };
        if want != shown {
            led.set(want);
            shown = want;
        }
    }
}
