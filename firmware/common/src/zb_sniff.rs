//! IEEE 802.15.4 sniffing — Zigbee and Thread reconnaissance.
//!
//! The nRF52840's RADIO speaks 802.15.4 natively (O-QPSK DSSS, 250 kbit/s,
//! channels 11–26 at 2405–2480 MHz), so this is the same peripheral every BLE
//! mode drives, with a different MODE/PCNF/CRC block — see
//! [`crate::common::radio_configure_154`]. It cannot run alongside the BLE modes:
//! there is one RADIO and switching MODE means a full disable and reconfigure, so
//! this is a boot mode of its own rather than a task.
//!
//! **What this mode can and cannot see.** The MAC header is in the clear, so
//! channels, PAN IDs, addresses, frame types, sequence numbers and the auxiliary
//! security header all decode. Payloads are AES-CCM* encrypted under a network
//! key we do not have. Thread is opaque without commissioning credentials; Zigbee
//! is decryptable only by someone holding the trust-centre link key and watching
//! a join. So the deliverable here is presence and topology, not content — which
//! is exactly the question "what is around" asks.
//!
//! Structure mirrors [`crate::ble_sniff`]: [`scan`] captures and copies into
//! [`RX_QUEUE`], re-arming the receiver immediately; [`log_task`] drains the queue
//! and decodes while the radio is listening again.
//!
//! **Why not `embassy_nrf::radio::ieee802154`.** That driver's `Radio::new` wants
//! a bound RADIO interrupt, and this build cannot wire that vector (see the note
//! in [`crate::ble_sniff::scan`]); it also takes `Peri<RADIO>` ownership, which
//! every other mode here contradicts by driving `pac::RADIO` directly. Its
//! register setup is still the reference the configuration was checked against.

use core::cell::UnsafeCell;
use core::fmt::Write;
use core::sync::atomic::Ordering;

use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Instant, Timer};

use crate::ble_sniff::fnv1a;
use crate::common::{radio_disable_silent, radio_ensure_disabled, zb_ch_freq};
use crate::{led, LogLine, Rng, SyncBuf};

// ── Channels ──────────────────────────────────────────────────────────────────

const CH_FIRST: u8 = 11;
const CH_LAST: u8 = 26;
const CH_COUNT: usize = (CH_LAST - CH_FIRST + 1) as usize;

// Dwell budget. Unlike BLE — where an advertiser rotates across 37/38/39 and the
// scanner must chase it — an 802.15.4 network picks one channel when it is formed
// and stays there for its lifetime, so the strategy is to park rather than hop.
//
// What decides *where* to park is not the energy sweep. ED was the obvious prior
// and it is the wrong one: a sample is 256 µs of integration, and 802.15.4 duty
// cycles are tiny — a mains-powered Zigbee router emits a link-status frame every
// ~15 s and a sleepy end device polls every few minutes, so ED essentially never
// catches one. What it does catch is Wi-Fi, which is continuous. Biasing dwell
// toward ED-hot channels therefore spends the budget on the 2.4 GHz channels
// least likely to host a mesh. Confirmed on the first capture (2026-08-04): the
// persistently hot channels were 16–19 and 21–24, exactly Wi-Fi 6 and 11, and
// 38 s of biased dwell caught nothing.
//
// So dwell is near-uniform, with extra time on the channels the ecosystem
// actually prefers. Per-channel duty cycle is what governs time-to-first-frame —
// it is `dwell[ch] / sum(dwell)`, independent of the absolute numbers — so the
// only real lever is how unevenly the budget is split.
const DWELL_BASE_MS: u64 = 50;
const DWELL_PREFERRED_MS: u64 = 150;
const DWELL_JITTER_MS: u32 = 15;

/// Channels that get [`DWELL_PREFERRED_MS`]: the four ZLL primary channels, which
/// sit in the gaps between Wi-Fi 1, 6 and 11 and are what Zigbee coordinators and
/// Thread border routers pick by default when left to choose. A network can be
/// anywhere in 11–26 and every channel is still visited every cycle; this only
/// says where to look first.
const PREFERRED_CH: [u8; 4] = [11, 15, 20, 25];

/// ED margin above the sweep's own floor at which a channel is flagged in the
/// `zb_ed` line. Relative rather than absolute dBm so it adapts to a noisy site.
/// It marks the line only — see the note above on why it must not drive dwell.
const ED_HOT_MARGIN_DB: i16 = 8;

/// Flash length for the retune and per-frame blinks. Same 1 ms the BLE modes
/// use: long enough to see, short enough that a burst of frames reads as a
/// flicker rather than as solid light.
const BLINK_MS: u64 = 1;

// ── LED ───────────────────────────────────────────────────────────────────────

/// A one-shot blink that never blocks the scan.
///
/// [`flash`](Blink::flash) lights the LED and records when it should go dark;
/// [`service`](Blink::service) turns it off once that instant has passed, called
/// from the poll loop that is running anyway. Awaiting the blink instead — light
/// it, `Timer::after(1 ms).await`, darken it — would be a millisecond of deafness
/// per frame and per retune, and the frames that go missing are exactly the ones
/// that follow another frame closely: acks, and the second half of any exchange.
struct Blink<'a, S: led::Sink> {
    leds: &'a mut S,
    off_at: Option<Instant>,
}

impl<S: led::Sink> Blink<'_, S> {
    /// Light `c` for [`BLINK_MS`]. Last writer wins: a frame arriving inside the
    /// retune flash re-colours it rather than queueing behind it.
    fn flash(&mut self, c: led::Rgb) {
        self.leds.set(c);
        self.off_at = Some(Instant::now() + Duration::from_millis(BLINK_MS));
    }

    /// Light `c` until something else changes it.
    fn hold(&mut self, c: led::Rgb) {
        self.leds.set(c);
        self.off_at = None;
    }

    fn off(&mut self) {
        self.leds.set(led::OFF);
        self.off_at = None;
    }

    /// Darken an expired flash. Cheap enough to call on every poll iteration.
    fn service(&mut self) {
        if let Some(t) = self.off_at
            && Instant::now() >= t
        {
            self.off();
        }
    }
}

/// EVENTS_PHYEND poll granularity, matching the BLE scanner's 150 µs. An ack airs
/// 192 µs (aTurnaroundTime) after the frame it answers and is itself ~200 µs long,
/// so a coarser poll would routinely tear the ack out of the buffer under the
/// data frame's snapshot.
const POLL_US: u64 = 150;

/// ED samples per channel. Each iteration is 128 µs of integration, so the full
/// 16-channel sweep costs roughly 16 × (2 × 128 µs + 40 µs ramp) ≈ 4.7 ms — paid
/// once per cycle against a cycle that is hundreds of milliseconds of dwell.
const ED_ITERATIONS: u32 = 2;

/// EVENTS_EDEND poll granularity. Integration is ~256 µs at [`ED_ITERATIONS`],
/// so this is a handful of polls per channel.
const ED_POLL_US: u64 = 64;

/// Bound on the ED wait, in the same spirit as [`crate::common::wait_disabled`]:
/// a missing EVENTS_EDEND must cost one skipped channel, not the whole program.
const ED_POLL_LIMIT: u32 = 32;

// ── Buffers ───────────────────────────────────────────────────────────────────

// EasyDMA receive buffer. Layout on reception (nRF52840 PS figure 124):
//   [0]            PHR — PSDU length, FCS included
//   [1 .. 1+n]     MAC frame, where n = PHR - 2 (the FCS is verified in hardware
//                  and never written to RAM)
//   [1+n]          LQI, appended by the hardware
// PHR maxes at 127, so 1 + 125 + 1 = 127 bytes are ever written; 128 rounds it.
static RX_BUF: SyncBuf<128> = SyncBuf::new();

/// Snapshot of the frame being processed, copied out of [`RX_BUF`]. PHYEND_START
/// re-arms the receiver in hardware the instant a frame completes, so [`RX_BUF`]
/// begins filling with the next one while we are still reading this — same race
/// the BLE scanner runs, handled the same way.
static PKT_BUF: SyncBuf<128> = SyncBuf::new();

// ── Decode queue ──────────────────────────────────────────────────────────────

const RX_QUEUE_DEPTH: usize = 8;

/// One captured frame, copied off the DMA path so the radio can re-arm before it
/// is decoded.
struct ZbPacket {
    t_air: Instant,
    /// MAC frame as received: FCF onwards, no PHR, no FCS.
    data: [u8; 128],
    len: u8,
    rssi_dbm: i16,
    lqi: u8,
    ch: u8,
}

static RX_QUEUE: Channel<CriticalSectionRawMutex, ZbPacket, RX_QUEUE_DEPTH> = Channel::new();

/// Copies a received MAC frame into the decode queue. A plain `fn` so the packet
/// is built on the stack and stays out of the scan task's future; a full queue
/// records a drop rather than blocking the capture path.
fn enqueue(frame: &[u8], t_air: Instant, ch: u8, rssi_dbm: i16, lqi: u8) {
    let len = frame.len().min(128);
    let mut p = ZbPacket {
        t_air,
        data: [0u8; 128],
        len: len as u8,
        rssi_dbm,
        lqi,
        ch,
    };
    p.data[..len].copy_from_slice(&frame[..len]);
    if RX_QUEUE.try_send(p).is_err() {
        stats_drop();
    }
}

/// Copies the just-completed frame out of the DMA buffer into [`PKT_BUF`],
/// returning `(payload length, LQI)`. The PHR's top bit is reserved, hence the
/// mask; a PHR under 2 is noise that synced on a stray 0xA7 and is clamped to
/// empty rather than underflowing.
fn snapshot_rx() -> (usize, u8) {
    let src = unsafe { &*RX_BUF.0.get() };
    let phr = (src[0] & 0x7F) as usize;
    let n = phr.saturating_sub(2).min(src.len() - 2);
    let dst = unsafe { &mut *PKT_BUF.0.get() };
    dst[..n].copy_from_slice(&src[1..1 + n]);
    // The hardware does not compute LQI for frames under 3 bytes.
    let lqi = if n >= 3 { src[1 + n] } else { 0 };
    (n, lqi)
}

// ── Periodic statistics ───────────────────────────────────────────────────────

const STATS_CYCLES: u32 = 8;

struct Stats {
    cycles: u32,
    frames: u32,
    /// Receptions that failed CRC. Not logged individually: the bytes of a frame
    /// that failed CRC are not trustworthy enough to decode, and on a quiet
    /// channel some of these are not frames at all. The count is the useful part.
    crc_err: u32,
    dropped: u32,
    torn: u32,
    strongest: i16,

    // ── Receive-path liveness ────────────────────────────────────────────────
    //
    // `frames=0 crc_err=0` is ambiguous: it is what an empty band looks like and
    // also what a misconfigured demodulator looks like. These three separate
    // them, and the ED sweep already rules out the analog path — it cannot
    // produce sane per-channel energy unless the receiver ramps and tunes.
    //
    //   fs>0, phyend=0  → frames are syncing; PHYEND is the wrong event to poll,
    //                     and PHYEND_START is not re-arming either
    //   fs=0            → nothing syncs: SFD/PLEN/CRC config, or an empty band
    //   states missing 3 → the receiver never reached RX at all
    /// EVENTS_FRAMESTART: the SFD correlated. The earliest proof that something
    /// on air demodulated as 802.15.4.
    framestart: u32,
    /// EVENTS_PHYEND: a reception ran to the end of the PSDU. This is the event
    /// the capture loop is built on, counted separately from the frames it
    /// yielded so a mismatch is visible.
    phyend: u32,
    /// Bitmask of `RADIO.STATE` values observed during dwells. Bit 3 (RX) set is
    /// the receiver actually listening; bit 2 (RXIDLE) alone means it ramped and
    /// stopped.
    states: u32,
}

struct StatsCell(UnsafeCell<Stats>);
unsafe impl Sync for StatsCell {}
static STATS: StatsCell = StatsCell(UnsafeCell::new(Stats {
    cycles: 0,
    frames: 0,
    crc_err: 0,
    dropped: 0,
    torn: 0,
    strongest: -128,
    framestart: 0,
    phyend: 0,
    states: 0,
}));

fn stats_frame(rssi_dbm: i16) {
    let s = unsafe { &mut *STATS.0.get() };
    s.frames += 1;
    if rssi_dbm > s.strongest {
        s.strongest = rssi_dbm;
    }
}

fn stats_crc_err() {
    unsafe { &mut *STATS.0.get() }.crc_err += 1;
}

fn stats_drop() {
    crate::ERR_TOTAL.fetch_add(1, Ordering::Relaxed);
    unsafe { &mut *STATS.0.get() }.dropped += 1;
}

fn stats_torn() {
    crate::ERR_TOTAL.fetch_add(1, Ordering::Relaxed);
    unsafe { &mut *STATS.0.get() }.torn += 1;
}

fn stats_framestart() {
    unsafe { &mut *STATS.0.get() }.framestart += 1;
}

fn stats_phyend() {
    unsafe { &mut *STATS.0.get() }.phyend += 1;
}

fn stats_state(state: u32) {
    unsafe { &mut *STATS.0.get() }.states |= 1 << (state & 0x1F);
}

/// Called once per scan cycle; emits and resets the window every [`STATS_CYCLES`],
/// then dumps the accumulated network table — which is the actual answer to "what
/// is around" and, unlike the window counters, is cumulative since boot.
fn stats_tick() {
    let s = unsafe { &mut *STATS.0.get() };
    s.cycles += 1;
    if s.cycles < STATS_CYCLES {
        return;
    }
    crate::ulogf!(
        "zb stats: cycles={} frames={} crc_err={} strongest={}dBm dev={} dropped={} torn={} \
         fs={} phyend={} states=0x{:04X}\r\n",
        s.cycles, s.frames, s.crc_err, s.strongest, device_count(), s.dropped, s.torn,
        s.framestart, s.phyend, s.states
    );
    *s = Stats {
        cycles: 0, frames: 0, crc_err: 0, dropped: 0, torn: 0, strongest: -128,
        framestart: 0, phyend: 0, states: 0,
    };
    nets_report();
}

// ── Network table ─────────────────────────────────────────────────────────────
//
// Distinct (PAN ID, channel) pairs with a frame count and whatever the beacons
// said the stack was. Small and fixed: a site with more than 16 coexisting PANs
// on one band is not a site this mode is going to characterise in one pass
// anyway, and `nets_report` says so when it fills.

const NET_SLOTS: usize = 16;

/// What a beacon payload identified the network as. Data frames alone cannot tell
/// Zigbee from Thread — both are ordinary secured 802.15.4 data frames — so this
/// stays [`Stack::Unknown`] until a beacon arrives.
#[derive(Clone, Copy, PartialEq)]
enum Stack {
    Unknown,
    Zigbee,
    Thread,
}

impl Stack {
    fn name(self) -> &'static str {
        match self {
            Stack::Unknown => "?",
            Stack::Zigbee => "zigbee",
            Stack::Thread => "thread",
        }
    }
}

#[derive(Clone, Copy)]
struct Net {
    pan: u16,
    ch: u8,
    used: bool,
    stack: Stack,
    frames: u32,
    best_rssi: i16,
}

struct NetTable(UnsafeCell<[Net; NET_SLOTS]>);
unsafe impl Sync for NetTable {}
static NETS: NetTable = NetTable(UnsafeCell::new(
    [Net { pan: 0, ch: 0, used: false, stack: Stack::Unknown, frames: 0, best_rssi: -128 }; NET_SLOTS],
));

/// Whether the table filled and dropped a PAN. Reported rather than silently
/// truncating: a table that overflowed is a survey that under-counts, and the
/// reader needs to know which of the two they are looking at.
static NETS_FULL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn net_note(pan: u16, ch: u8, rssi_dbm: i16, stack: Stack) {
    let t = unsafe { &mut *NETS.0.get() };
    for n in t.iter_mut() {
        if n.used && n.pan == pan && n.ch == ch {
            n.frames += 1;
            if rssi_dbm > n.best_rssi {
                n.best_rssi = rssi_dbm;
            }
            // A beacon upgrades Unknown; it never downgrades a known stack.
            if stack != Stack::Unknown {
                n.stack = stack;
            }
            return;
        }
    }
    for n in t.iter_mut() {
        if !n.used {
            *n = Net { pan, ch, used: true, stack, frames: 1, best_rssi: rssi_dbm };
            return;
        }
    }
    NETS_FULL.store(true, Ordering::Relaxed);
}

fn nets_report() {
    let t = unsafe { &*NETS.0.get() };
    for n in t.iter().filter(|n| n.used) {
        crate::ulogf!(
            "zb net: pan=0x{:04X} ch={} stack={} frames={} best={}dBm\r\n",
            n.pan, n.ch, n.stack.name(), n.frames, n.best_rssi
        );
    }
    if NETS_FULL.load(Ordering::Relaxed) {
        crate::ulogf!("zb net: table full ({} slots) — further PANs not counted\r\n", NET_SLOTS);
    }
}

// ── Device set ────────────────────────────────────────────────────────────────
//
// Distinct source addresses seen, as 16-bit fingerprints in an open-addressed
// set. Fingerprints rather than addresses because the only question asked of it
// is "how many", and a short address and an extended address for the same device
// are two entries either way. Cumulative since boot; no eviction, so `dev=`
// saturating at DEV_SLOTS is itself the signal that the site is busier than this
// table can describe.

const DEV_SLOTS: usize = 128;

struct DevSet(UnsafeCell<[u16; DEV_SLOTS]>);
unsafe impl Sync for DevSet {}
static DEVS: DevSet = DevSet(UnsafeCell::new([0u16; DEV_SLOTS]));
static DEV_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn device_note(addr: &[u8]) {
    // 0 is the empty marker, so fold it onto a non-zero value rather than
    // carrying an occupancy bitmap for one collision in 65536.
    let fp = match fnv1a(addr) as u16 {
        0 => 1,
        v => v,
    };
    let t = unsafe { &mut *DEVS.0.get() };
    let mut i = (fp as usize) % DEV_SLOTS;
    for _ in 0..DEV_SLOTS {
        match t[i] {
            0 => {
                t[i] = fp;
                DEV_COUNT.fetch_add(1, Ordering::Relaxed);
                return;
            }
            v if v == fp => return,
            _ => i = (i + 1) % DEV_SLOTS,
        }
    }
}

fn device_count() -> u32 {
    DEV_COUNT.load(Ordering::Relaxed)
}

// ── Energy detection ──────────────────────────────────────────────────────────

/// One ED sample converted to dBm.
///
/// The nRF reports ED as a 0..63 code; the linear conversion puts code 0 at about
/// -93 dBm in 1 dB steps. Approximate on purpose — the sweep ranks channels
/// against each other to decide where to dwell, and nothing downstream treats it
/// as a calibrated power measurement.
fn ed_dbm(sample: u8) -> i16 {
    -93 + (sample.min(63) as i16)
}

/// Samples the energy on every channel, filling `out` with dBm estimates.
///
/// This runs whether or not anything is decodable, and that is most of its value:
/// on a site with no 802.15.4 traffic at all it still shows where the Wi-Fi is
/// (channels 11–14, 16–19 and 21–24 overlap Wi-Fi 1, 6 and 11), which is the
/// difference between "nothing is here" and "the receiver is not working".
async fn ed_sweep(out: &mut [i16; CH_COUNT]) {
    let r = pac::RADIO;
    for (i, slot) in out.iter_mut().enumerate() {
        let ch = CH_FIRST + i as u8;
        let Some(freq) = zb_ch_freq(ch) else { continue };

        radio_disable_silent();
        r.frequency().write(|w| {
            w.set_frequency(freq);
            w.set_map(vals::Map::Default);
        });
        r.edcnt().write(|w| w.set_edcnt(ED_ITERATIONS));
        r.events_edend().write_value(0);
        // READY→EDSTART begins integration as soon as the receiver has ramped, so
        // the CPU never has to observe the intermediate state.
        r.shorts().write(|w| w.set_ready_edstart(true));
        r.tasks_rxen().write_value(1);

        // Awaited rather than spun on: the whole sweep is ~4.7 ms of radio time
        // and a blocking wait would be 4.7 ms of unserviced USB CDC every cycle.
        let mut polls = 0u32;
        while r.events_edend().read() == 0 {
            polls += 1;
            if polls >= ED_POLL_LIMIT {
                break;
            }
            Timer::after_micros(ED_POLL_US).await;
        }
        if polls < ED_POLL_LIMIT {
            r.events_edend().write_value(0);
            *slot = ed_dbm(r.edsample().read().edlvl());
        }
        r.shorts().write(|_w| {});
        radio_disable_silent();
    }
}

/// Emits the sweep and returns the per-channel dwell in milliseconds.
///
/// Marks in the `zb_ed` line, which describe two independent things:
///   * `*` — a [`PREFERRED_CH`] channel, getting the longer dwell
///   * `#` — [`ED_HOT_MARGIN_DB`] or more above this sweep's quietest channel.
///     Read as "something continuous is transmitting here", which in the 2.4 GHz
///     band is Wi-Fi far more often than it is a mesh.
///   * `:` — neither
fn plan_dwell(ed: &[i16; CH_COUNT]) -> [u64; CH_COUNT] {
    let floor = ed.iter().copied().min().unwrap_or(-93);
    let mut dwell = [DWELL_BASE_MS; CH_COUNT];

    let mut s = LogLine::new();
    let _ = s.push_str("zb_ed");
    for (i, &v) in ed.iter().enumerate() {
        let ch = CH_FIRST + i as u8;
        let preferred = PREFERRED_CH.contains(&ch);
        if preferred {
            dwell[i] = DWELL_PREFERRED_MS;
        }
        let mark = if preferred {
            "*"
        } else if v >= floor + ED_HOT_MARGIN_DB {
            "#"
        } else {
            ":"
        };
        let _ = write!(s, " {}{}{}", ch, mark, v);
    }
    crate::terminate_line(&mut s);
    crate::log_send(s);

    dwell
}

// ── Capture ───────────────────────────────────────────────────────────────────

/// One survey cycle: an energy sweep across 11–26, then a dwell on each channel
/// sized by what the sweep found.
///
/// The LED narrates which of the three phases the mode is in, because they are
/// otherwise indistinguishable from outside and they fail differently: solid
/// **green** for the whole energy sweep, a **red** flash at each channel change,
/// and a **blue** flash per captured frame. A run stuck green never finished a
/// sweep; one that only flashes red is sweeping and dwelling but hearing nothing.
pub async fn scan(rng: &mut Rng, leds: &mut impl led::Sink) {
    let mut led = Blink { leds, off_at: None };

    let mut ed = [-128i16; CH_COUNT];
    // Held for the sweep rather than flashed per sample: the whole sweep is
    // ~4.7 ms, so a per-channel blink would be one green flicker either way.
    led.hold(led::GREEN);
    ed_sweep(&mut ed).await;
    led.off();
    let dwell_ms = plan_dwell(&ed);

    // Visit order is reshuffled every cycle for the same reason the BLE scanner
    // shuffles: a fixed order gives every channel a fixed sampling phase, and a
    // periodic transmitter can sit in the gap forever.
    let mut order = [0usize; CH_COUNT];
    for (i, slot) in order.iter_mut().enumerate() {
        *slot = i;
    }
    for i in (1..CH_COUNT).rev() {
        let j = rng.below((i + 1) as u32) as usize;
        order.swap(i, j);
    }

    for &i in order.iter() {
        let ch = CH_FIRST + i as u8;
        let Some(freq) = zb_ch_freq(ch) else { continue };
        dwell_channel(ch, freq, dwell_ms[i], rng, &mut led).await;
    }
    led.off();

    stats_tick();
}

/// Holds the receiver open on one channel, queueing every frame that passes CRC.
async fn dwell_channel(ch: u8, freq: u8, ms: u64, rng: &mut Rng, led: &mut Blink<'_, impl led::Sink>) {
    let r = pac::RADIO;

    // Retune flash. Started here and darkened by `service` inside the poll loop
    // below, so the receiver is armed immediately and the flash overlaps the
    // first millisecond of listening. At 16 channels a cycle this is the mode's
    // heartbeat — if it stops, the scan loop is wedged.
    led.flash(led::RED);

    radio_ensure_disabled();
    r.frequency().write(|w| {
        w.set_frequency(freq);
        w.set_map(vals::Map::Default);
    });
    r.packetptr().write_value(RX_BUF.0.get() as u32);

    r.events_phyend().write_value(0);
    r.events_framestart().write_value(0);
    r.events_crcok().write_value(0);
    r.events_crcerror().write_value(0);
    r.events_address().write_value(0);
    r.events_disabled().write_value(0);
    // RXREADY→START begins reception once the receiver has ramped;
    // ADDRESS→RSSISTART samples signal strength at SFD match; PHYEND→START is the
    // 802.15.4 counterpart of the BLE path's END_START — it re-arms in hardware
    // the instant a frame completes, which is the only way to catch the ack that
    // airs 192 µs later.
    r.shorts().write(|w| {
        w.set_rxready_start(true);
        w.set_address_rssistart(true);
        w.set_phyend_start(true);
    });
    r.tasks_rxen().write_value(1);

    let dwell = Duration::from_micros((ms + rng.below(DWELL_JITTER_MS) as u64) * 1000);
    let deadline = Instant::now() + dwell;

    while Instant::now() < deadline {
        led.service();

        // Liveness sampling, independent of the capture path. FRAMESTART fires on
        // SFD correlation, well before the frame is complete, so it counts sync
        // attempts whether or not they turn into packets — and the state sample
        // says whether the receiver is listening at all.
        if r.events_framestart().read() != 0 {
            r.events_framestart().write_value(0);
            stats_framestart();
        }
        stats_state(r.state().read().0);

        if r.events_phyend().read() == 0 {
            Timer::after_micros(POLL_US).await;
            continue;
        }
        stats_phyend();
        // A frame completed. The receiver is already listening again, so
        // everything below races the next frame's DMA: read the per-frame
        // registers first, then snapshot, then check whether we won.
        r.events_phyend().write_value(0);
        let t_end = Instant::now();
        // CRCSTATUS, not EVENTS_CRCOK. PHYEND fires at the end of the PHY
        // payload, and in 802.15.4 the FCS is part of that payload, so the
        // status register is valid here — but the event is a separate signal
        // with its own timing, and `embassy_nrf`'s driver reads the register at
        // exactly this point. Following the reference removes a hypothesis.
        let crc_ok = r.crcstatus().read().crcstatus() == vals::Crcstatus::CrcOk;
        r.events_crcok().write_value(0);
        r.events_crcerror().write_value(0);
        let rssi_dbm = -(r.rssisample().read().rssisample() as i16);

        if !crc_ok {
            stats_crc_err();
            continue;
        }

        r.events_address().write_value(0);
        let (n, lqi) = snapshot_rx();
        if r.events_address().read() != 0 {
            stats_torn();
            continue;
        }
        if n == 0 {
            continue;
        }

        // Air time: preamble (4) + SFD (1) + PHR (1) + PSDU, at 250 kbit/s, which
        // is 32 µs per byte. PSDU is the payload plus the 2 FCS bytes the radio
        // stripped, so the frame occupied (6 + n + 2) × 32 µs before PHYEND.
        let t_air = t_end - Duration::from_micros((8 + n as u64) * 32);

        stats_frame(rssi_dbm);
        // Blue per captured frame, against a dark idle. No await here: the
        // receiver is already re-armed and the next frame — an ack, 192 µs out —
        // would land inside the blink.
        led.flash(led::BLUE);
        enqueue(&unsafe { &*PKT_BUF.0.get() }[..n], t_air, ch, rssi_dbm, lqi);
    }

    radio_disable_silent();
}

// ── MAC header decode ─────────────────────────────────────────────────────────
//
// IEEE 802.15.4-2015 clause 7.2. Only the header is parsed: everything past it is
// either an information element (skipped) or ciphertext.

#[derive(Clone, Copy)]
enum Addr {
    Short(u16),
    Ext([u8; 8]),
}

struct Mhr {
    ftype: u8,
    security: bool,
    pending: bool,
    ack_req: bool,
    ie_present: bool,
    version: u8,
    seq: Option<u8>,
    dst_pan: Option<u16>,
    dst: Option<Addr>,
    src_pan: Option<u16>,
    src: Option<Addr>,
    sec_level: u8,
    key_id_mode: u8,
    frame_counter: Option<u32>,
    /// Bytes consumed by the header — where the payload (or the IE list) starts.
    hdr_len: usize,
}

fn ftype_name(t: u8) -> &'static str {
    match t {
        0 => "BEACON",
        1 => "DATA",
        2 => "ACK",
        3 => "CMD",
        4 => "MULTIPURPOSE",
        5 => "FRAGMENT",
        6 => "EXTENDED",
        _ => "RESERVED",
    }
}

fn cmd_name(id: u8) -> &'static str {
    match id {
        0x01 => "AssocReq",
        0x02 => "AssocResp",
        0x03 => "DisassocNotify",
        0x04 => "DataReq",
        0x05 => "PanIdConflict",
        0x06 => "OrphanNotify",
        0x07 => "BeaconReq",
        0x08 => "CoordRealign",
        0x09 => "GtsReq",
        _ => "?",
    }
}

/// Which PAN ID fields are present, per clause 7.2.1.5.
///
/// Frame version 2 replaced the simple "destination PAN unless suppressed, source
/// PAN unless compressed" rule with Table 7-2, where the compression bit's meaning
/// depends on both addressing modes. Thread runs version 2 almost exclusively, so
/// parsing it with the legacy rule mis-frames every Thread packet by two bytes —
/// which then shows up as plausible-looking garbage addresses rather than an
/// obvious failure.
fn pan_presence(version: u8, dst_mode: u8, src_mode: u8, compress: bool) -> (bool, bool) {
    if version < 2 {
        return (dst_mode != 0, src_mode != 0 && !compress);
    }
    let dst = dst_mode != 0;
    let src = src_mode != 0;
    match (dst, src, compress) {
        (false, false, false) => (false, false),
        (false, false, true) => (true, false),
        (true, false, false) => (true, false),
        (true, false, true) => (false, false),
        (false, true, false) => (false, true),
        (false, true, true) => (false, false),
        // Both addresses present: extended/extended shares one PAN, so the
        // destination PAN carries it and the source PAN is always absent.
        (true, true, c) => {
            if dst_mode == 3 && src_mode == 3 {
                (!c, false)
            } else {
                (true, !c)
            }
        }
    }
}

fn take_addr(f: &[u8], off: &mut usize, mode: u8) -> Option<Addr> {
    match mode {
        2 => {
            let v = u16::from_le_bytes([*f.get(*off)?, *f.get(*off + 1)?]);
            *off += 2;
            Some(Addr::Short(v))
        }
        3 => {
            let mut a = [0u8; 8];
            a.copy_from_slice(f.get(*off..*off + 8)?);
            *off += 8;
            Some(Addr::Ext(a))
        }
        _ => None,
    }
}

fn take_u16(f: &[u8], off: &mut usize) -> Option<u16> {
    let v = u16::from_le_bytes([*f.get(*off)?, *f.get(*off + 1)?]);
    *off += 2;
    Some(v)
}

/// Parses the MAC header. `None` when the frame is shorter than the header its
/// own control field describes — a truncated capture or a CRC-passing fluke.
fn parse_mhr(f: &[u8]) -> Option<Mhr> {
    let fcf = u16::from_le_bytes([*f.first()?, *f.get(1)?]);
    let mut off = 2usize;

    let ftype = (fcf & 0x0007) as u8;
    let security = fcf & 0x0008 != 0;
    let pending = fcf & 0x0010 != 0;
    let ack_req = fcf & 0x0020 != 0;
    let compress = fcf & 0x0040 != 0;
    let seq_suppress = fcf & 0x0100 != 0;
    let ie_present = fcf & 0x0200 != 0;
    let dst_mode = ((fcf >> 10) & 0x3) as u8;
    let version = ((fcf >> 12) & 0x3) as u8;
    let src_mode = ((fcf >> 14) & 0x3) as u8;

    // Sequence-number suppression exists only from frame version 2.
    let seq = if version >= 2 && seq_suppress {
        None
    } else {
        let v = *f.get(off)?;
        off += 1;
        Some(v)
    };

    let (has_dst_pan, has_src_pan) = pan_presence(version, dst_mode, src_mode, compress);
    let dst_pan = if has_dst_pan { Some(take_u16(f, &mut off)?) } else { None };
    let dst = take_addr(f, &mut off, dst_mode);
    if dst_mode >= 2 && dst.is_none() {
        return None;
    }
    let src_pan = if has_src_pan { Some(take_u16(f, &mut off)?) } else { None };
    let src = take_addr(f, &mut off, src_mode);
    if src_mode >= 2 && src.is_none() {
        return None;
    }

    // Auxiliary security header (clause 7.4). In the clear even when the payload
    // is not, and its key identifier mode and frame counter are a usable
    // fingerprint for which stack produced the frame.
    let mut sec_level = 0;
    let mut key_id_mode = 0;
    let mut frame_counter = None;
    if security {
        let scf = *f.get(off)?;
        off += 1;
        sec_level = scf & 0x07;
        key_id_mode = (scf >> 3) & 0x03;
        let fc_suppressed = scf & 0x20 != 0;
        if !fc_suppressed {
            let b = f.get(off..off + 4)?;
            frame_counter = Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            off += 4;
        }
        // Key identifier: mode 0 implicit, 1 = index only, 2 = 4-byte source +
        // index, 3 = 8-byte source + index.
        off += match key_id_mode {
            1 => 1,
            2 => 5,
            3 => 9,
            _ => 0,
        };
        if off > f.len() {
            return None;
        }
    }

    Some(Mhr {
        ftype, security, pending, ack_req, ie_present, version, seq,
        dst_pan, dst, src_pan, src, sec_level, key_id_mode, frame_counter,
        hdr_len: off,
    })
}

/// Identifies the stack from a beacon payload.
///
/// A beacon's MAC payload begins with a protocol ID: Zigbee uses 0x00, Thread
/// 0x03. This is the only frame that says outright which mesh it belongs to —
/// every data frame from either looks identical at the MAC layer — so it is worth
/// walking the superframe, GTS and pending-address fields to reach it.
fn beacon_stack(payload: &[u8]) -> Stack {
    // Superframe specification (2) + GTS specification (1).
    let gts_spec = match payload.get(2) {
        Some(&v) => v,
        None => return Stack::Unknown,
    };
    let mut off = 3usize;
    let gts_count = (gts_spec & 0x07) as usize;
    if gts_count > 0 {
        // GTS directions (1) + one 3-byte descriptor per GTS.
        off += 1 + 3 * gts_count;
    }
    let pend = match payload.get(off) {
        Some(&v) => v,
        None => return Stack::Unknown,
    };
    off += 1;
    off += 2 * ((pend & 0x07) as usize) + 8 * (((pend >> 4) & 0x07) as usize);

    match payload.get(off) {
        Some(0x00) => Stack::Zigbee,
        Some(0x03) => Stack::Thread,
        _ => Stack::Unknown,
    }
}

// ── Logging ───────────────────────────────────────────────────────────────────

/// Drains [`RX_QUEUE`], decoding and logging one frame at a time while the radio
/// is listening. `with_log_stamp` gives every line the frame's air time.
#[embassy_executor::task]
pub async fn log_task() -> ! {
    loop {
        let p = RX_QUEUE.receive().await;
        crate::with_log_stamp(p.t_air, || emit(&p));
    }
}

fn write_addr(s: &mut LogLine, a: &Addr) {
    match a {
        Addr::Short(v) => {
            let _ = write!(s, "0x{:04X}", v);
        }
        Addr::Ext(b) => {
            // Printed big-endian (transmission order reversed) so the leading
            // bytes are the OUI, which is how an EUI-64 is normally read.
            let _ = write!(
                s, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]
            );
        }
    }
}

fn emit(p: &ZbPacket) {
    let f = &p.data[..p.len as usize];

    let Some(m) = parse_mhr(f) else {
        crate::ulogf!(
            "zb ch={} {}dBm lqi={} MALFORMED len={}\r\n",
            p.ch, p.rssi_dbm, p.lqi, f.len()
        );
        crate::hexdump(f, 0, 2);
        return;
    };

    let payload = &f[m.hdr_len.min(f.len())..];

    // A beacon is the only frame that names its stack; everything else inherits
    // whatever a beacon on the same PAN established earlier.
    let stack = if m.ftype == 0 { beacon_stack(payload) } else { Stack::Unknown };
    if let Some(pan) = m.src_pan.or(m.dst_pan) {
        net_note(pan, p.ch, p.rssi_dbm, stack);
    }
    if let Some(a) = &m.src {
        match a {
            Addr::Short(v) => device_note(&v.to_le_bytes()),
            Addr::Ext(b) => device_note(b),
        }
    }

    let mut s = LogLine::new();
    let _ = write!(
        s, "zb ch={} {}dBm lqi={} {} v{}",
        p.ch, p.rssi_dbm, p.lqi, ftype_name(m.ftype), m.version
    );
    if let Some(q) = m.seq {
        let _ = write!(s, " seq={}", q);
    }
    if let Some(pan) = m.dst_pan {
        let _ = write!(s, " dpan=0x{:04X}", pan);
    }
    if let Some(a) = &m.dst {
        let _ = s.push_str(" dst=");
        write_addr(&mut s, a);
    }
    if let Some(pan) = m.src_pan {
        let _ = write!(s, " spar=0x{:04X}", pan);
    }
    if let Some(a) = &m.src {
        let _ = s.push_str(" src=");
        write_addr(&mut s, a);
    }
    if m.security {
        let _ = write!(s, " sec=L{}/K{}", m.sec_level, m.key_id_mode);
        if let Some(fc) = m.frame_counter {
            let _ = write!(s, " fc={}", fc);
        }
    }
    if m.ftype == 3
        && let Some(&id) = payload.first()
    {
        let _ = write!(s, " cmd={}", cmd_name(id));
    }
    if stack != Stack::Unknown {
        let _ = write!(s, " stack={}", stack.name());
    }
    if m.pending {
        let _ = s.push_str(" pending");
    }
    if m.ack_req {
        let _ = s.push_str(" ack_req");
    }
    if m.ie_present {
        let _ = s.push_str(" ie");
    }
    crate::terminate_line(&mut s);
    crate::log_send(s);

    // Header in the annotated dump — it has field boundaries worth lining offsets
    // up against. Encrypted payloads go to the dense dump for the reason given at
    // `hexdump_dense`: ciphertext has no readable side, and 16-bytes-to-a-row
    // would cost eight lines of a 32-slot LOG channel per frame.
    crate::hexdump(&f[..m.hdr_len.min(f.len())], 0, 2);
    if !payload.is_empty() {
        if m.security {
            crate::hexdump_dense("sec", payload, 2);
        } else {
            crate::hexdump(payload, m.hdr_len, 2);
        }
    }
}
