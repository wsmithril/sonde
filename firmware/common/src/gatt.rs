//! Active GATT enumeration — BLE central role.
//!
//! Unlike the passive sniffer ([`crate::ble_sniff`]), this mode *transmits*: it
//! surveys connectable advertisers, opens a connection to the strongest one not
//! seen in the last hour, walks its attribute database (services →
//! characteristics → descriptors), reads each readable characteristic value,
//! prints the table over USB serial, tears the connection down, and repeats.
//!
//! All GATT/ATT decoding lives in this module (the shared `decoder` handles only
//! advertising payloads). Radio primitives shared with the sniffer come from
//! [`crate::common`].
//!
//! ## How the connection is driven
//!
//! Two moments need turnaround the executor cannot schedule in software:
//!   1. RX target `ADV_IND` → TX `CONNECT_IND` exactly T_IFS (150 µs) later.
//!   2. Each connection event: master TX → RX peer reply, T_IFS later.
//!
//! Both use the RADIO's hardware inter-frame handling — `TIFS=150` plus a shorts
//! chain that makes the radio flip direction and insert the gap by itself.
//! (1) chains `end_disable` + `disabled_txen` + `txready_start`; (2) chains
//! `txready_start` + `end_disable` + `disabled_rxen` + `rxready_start`. Software
//! only disarms the direction-flip short once it has fired, so neither chain
//! loops. `PACKETPTR` is *latched at each START
//! task*, so swapping it after a START safely redirects only the next
//! transfer. Connection-event *anchors* are absolute `Timer::at` deadlines (as in
//! [`crate::ble_sniff::follow_aux`]); within an event we busy-poll the sub-ms
//! events so reaction stays tight.
//!
//! ## Onboard LED
//!
//! The colours mean something different here than in sniffer mode:
//!
//! | Colour        | Meaning |
//! |---------------|---------|
//! | Off           | surveying the advertising channels |
//! | Green flash   | a connectable peer is in range — including one the "seen in the last hour" filter will skip, so an all-known room still shows life |
//! | Blue          | last connection event: we transmitted, the peer did not answer |
//! | Red           | last connection event: the peer answered |
//! | Yellow flash  | the attempt failed — CONNECT_IND refused, or the link formed and yielded no services |
//!
//! Blue and red are set once per connection event and held for the whole 31.25 ms
//! interval, so a healthy enumeration reads as steady red with blue flickers on
//! retransmits, and a link that never comes up is solid blue.
//!
//! ## Constraints (v1)
//! * No pairing/encryption — reads that need it return an ATT error (printed).
//! * Legacy 1M connectable advertising only (`ADV_IND`/`ADV_DIRECT_IND`).
//! * ATT_MTU is negotiated up to [`ATT_MTU_MAX`] via Exchange MTU at the start of
//!   [`enumerate`], falling back to 23; frames larger than one LL PDU are
//!   reassembled ([`Reasm`]).
//! * Channel Selection Algorithm #1 with a full channel map.
//! * A peer whose database was walked is not walked again for an hour
//!   ([`RECENT_WINDOW_S`]); an attempt that yielded nothing is retried after
//!   [`RETRY_COOLDOWN_S`]. Both windows are session-scoped (uptime `Instant`) and
//!   keyed on the advertised address, so they do not survive the reset that
//!   cycles boot modes, and a peer that rotates its RPA looks like a new device.

use core::cell::UnsafeCell;

use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;
use embassy_time::{Duration, Instant, Timer};
use heapless::Vec;

use crate::common::{
    data_ch_freq, radio_configure_ble, radio_disable_silent, radio_ensure_disabled,
    set_access_address, set_pcnf0, ADV_AA, ADV_CRC_POLY,
};
use crate::decoder::protocol::Decoder as _; // `.decode()` on the ATT channel decoder
use crate::{decoder, led, Rng};

// ── Connection parameters (our choices as master) ─────────────────────────────

const T_IFS_US: u16 = 150; // inter-frame spacing enforced by the RADIO
const OUR_CRC_INIT: u32 = 0x0012_3456; // per-connection CRC init (24-bit)

/// Fallback access address, used only if [`pick_access_address`] somehow fails to
/// draw a spec-legal value. Many transitions, no long runs — it was the fixed AA
/// this firmware used before randomisation.
const FALLBACK_AA: u32 = 0xA5B6_C9D3;

/// Access address for the connection currently being set up. Redrawn per
/// `CONNECT_IND` by [`pick_access_address`] and read back by
/// [`build_connect_ind`] and [`configure_conn_radio`], which run at different
/// points in the attempt and so cannot take it as a parameter without threading
/// it through everything in between.
///
/// The AA has to be per-connection: it is what a receiver uses to tell one
/// link's packets from another's, and the spec (Core v5.4 Vol 6 Part B §2.1.2)
/// requires a fresh one each time. Reusing a constant also made every attempt in
/// a capture look alike, so a stale link and a new one to the same peer were
/// indistinguishable in the log.
static CONN_AA: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(FALLBACK_AA);

fn conn_aa() -> u32 {
    CONN_AA.load(core::sync::atomic::Ordering::Relaxed)
}

/// CRCInit and hop increment for the connection currently being set up. Like the
/// access address these are per-connection choices the master makes and puts in
/// the `CONNECT_IND`, and like it they are read at two points in the attempt —
/// `build_connect_ind` puts them on air, `configure_conn_radio` and the channel
/// walk consume them — so they live here rather than being threaded through.
///
/// Drawing them per link matters for the same reason the AA does: held constant,
/// every connection walks the identical channel ladder (`ch = hop·ev mod 37`) and
/// carries the identical CRC seed, so two captures of different links are
/// indistinguishable and a systematic channel fault cannot be told apart from an
/// unlucky one.
static CONN_CRC_INIT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(OUR_CRC_INIT);
static CONN_HOP: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(HOP_INCREMENT as u32);

fn conn_crc_init() -> u32 {
    CONN_CRC_INIT.load(core::sync::atomic::Ordering::Relaxed)
}

fn conn_hop() -> u8 {
    CONN_HOP.load(core::sync::atomic::Ordering::Relaxed) as u8
}

/// Redraw the per-connection CRC seed (any 24-bit value) and hop increment
/// (CSA#1 requires 5..=16, Core v5.4 Vol 6 Part B §4.5.8.2).
fn pick_conn_params(rng: &mut Rng) {
    use core::sync::atomic::Ordering::Relaxed;
    CONN_CRC_INIT.store(rng.next_u32() & 0x00FF_FFFF, Relaxed);
    CONN_HOP.store(5 + rng.below(12), Relaxed);
}

/// The access-address validity rules from Core v5.4 Vol 6 Part B §2.1.2, for an
/// uncoded PHY. Bits are counted in *transmission* order — LSB of octet 0 goes
/// out first — so bit `i` of the `u32` is the `i`-th bit on air and "the six most
/// significant bits" are 26..=31.
fn aa_valid(aa: u32) -> bool {
    if aa == ADV_AA {
        return false;
    }
    // "Shall not be a sequence that differs from the advertising AA by only one
    // bit" — a single-bit error on an advertising packet must not be able to
    // masquerade as this connection.
    if (aa ^ ADV_AA).count_ones() <= 1 {
        return false;
    }
    let b = aa.to_le_bytes();
    if b[0] == b[1] && b[1] == b[2] && b[2] == b[3] {
        return false;
    }
    // Bit `i` of `trans` is set when bit `i+1` differs from bit `i`, so bits
    // 0..=30 are the 31 adjacent pairs.
    let trans = (aa ^ (aa >> 1)) & 0x7FFF_FFFF;
    if trans.count_ones() > 24 {
        return false;
    }
    // At least two transitions within bits 26..=31, i.e. among pairs 26..=30.
    if ((trans >> 26) & 0x1F).count_ones() < 2 {
        return false;
    }
    // No more than six consecutive identical bits.
    let mut run = 1u32;
    for i in 1..32 {
        if (aa >> i) & 1 == (aa >> (i - 1)) & 1 {
            run += 1;
            if run > 6 {
                return false;
            }
        } else {
            run = 1;
        }
    }
    true
}

/// Draws a spec-legal access address. About two thirds of random 32-bit values
/// pass [`aa_valid`] (measured over 200k samples; the six-MSB transition rule is
/// what rejects most of the rest), so the loop nearly always exits within a few
/// draws. The bound only exists to keep a degenerate PRNG state from hanging the
/// connection path.
fn pick_access_address(rng: &mut Rng) -> u32 {
    for _ in 0..64 {
        let aa = rng.next_u32();
        if aa_valid(aa) {
            return aa;
        }
    }
    FALLBACK_AA
}
// ×1.25 ms between connection events. Chosen so the interval is a whole number
// of timer ticks: 25 × 1.25 ms = 31.25 ms = exactly 1024 ticks at 32768 Hz. With
// a non-exact interval (36 → 45 ms → 1474.56 ticks) `Duration::from_micros`
// truncates and the anchor loses ~17 µs *per event* — a 380 ppm drift away from
// the peer's clock that walks us out of its receive window within a few events.
const CONN_INTERVAL: u16 = 25;
/// [`CONN_INTERVAL`] as timer ticks. The assert below fails the build if the
/// interval is ever changed to a value that is not tick-exact.
const CONN_INTERVAL_TICKS: u64 =
    (CONN_INTERVAL as u64 * 1250 * embassy_time::TICK_HZ) / 1_000_000;
const _: () = assert!(
    CONN_INTERVAL_TICKS * 1_000_000 == CONN_INTERVAL as u64 * 1250 * embassy_time::TICK_HZ
);
const CONN_LATENCY: u16 = 0;
const CONN_TIMEOUT: u16 = 300; // ×10 ms = 3 s supervision (we track it as an event budget)
const WIN_SIZE: u8 = 2; // ×1.25 ms transmit-window width
const WIN_OFFSET: u16 = 2; // ×1.25 ms; delays the first anchor to leave time to reconfigure
const HOP_INCREMENT: u8 = 7; // CSA#1 hop (5..16)
const TX_WIN_DELAY_US: u64 = 1250; // fixed transmitWindowDelay for a CONNECT_IND

/// Our address (Initiator address in CONNECT_IND). Random static: the two MSBs of
/// the most-significant octet (`buf[7]`, i.e. index 5 here) are 0b11.
/// Our BD_ADDR as an initiator, on-air order (LSB first), regenerated for every
/// connection attempt by [`randomize_our_addr`].
///
/// A fixed address makes the probe trivially trackable across a building and
/// lets a peer that has refused us once refuse us on sight. The type is random
/// static, so the two most significant bits of the display-order MSB — index 5
/// here — are 0b11, and the remaining 46 bits must not be all-zero or all-one.
struct OurAddr(UnsafeCell<[u8; 6]>);
unsafe impl Sync for OurAddr {}
static OUR_ADDR: OurAddr = OurAddr(UnsafeCell::new([0x11, 0x22, 0x33, 0x44, 0x55, 0xC6]));

fn our_addr() -> [u8; 6] {
    unsafe { *OUR_ADDR.0.get() }
}

/// Draws a fresh random static address. Called once per connection attempt, so
/// the address is stable for the life of a link but never reused across two.
fn randomize_our_addr(rng: &mut Rng) {
    let a = unsafe { &mut *OUR_ADDR.0.get() };
    loop {
        let (lo, hi) = (rng.next_u32(), rng.next_u32());
        a[0..4].copy_from_slice(&lo.to_le_bytes());
        a[4..6].copy_from_slice(&hi.to_le_bytes()[..2]);
        a[5] |= 0xC0; // random static
        // Reject the two reserved patterns: all-zero and all-one random part.
        let rest = [a[0], a[1], a[2], a[3], a[4], a[5] & 0x3F];
        if !rest.iter().all(|&b| b == 0) && rest != [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F] {
            return;
        }
    }
}

// ── Event / discovery budgets ─────────────────────────────────────────────────

const MAX_EVENTS_PER_TXN: u32 = 60; // connection events to await one ATT response
const MAX_CONSEC_MISS: u32 = 40; // consecutive peer no-shows on a *live* link → lost
// Consecutive no-shows tolerated *before the peer has ever replied*. Three in
// four accepted connections in captured runs are silent: the CONNECT_IND is
// taken but the peer never sends a single data-channel PDU (already bonded to
// its phone, privacy policy, or an anchor outside its window). Live peers, by
// contrast, answer within the first few events (ev=1..4 observed). Waiting the
// full 40 events (~1.2 s) on a peer that will never speak is pure dead time, so
// bail early until the link proves itself, then extend to MAX_CONSEC_MISS.
const MAX_CONSEC_MISS_UNPROVEN: u32 = 10;
const MAX_SERVICES: usize = 16;
const MAX_CHARS_PER_SVC: usize = 24;

/// ATT MTU before any Exchange MTU — the spec default (23) and the negotiation
/// floor.
const ATT_MTU_DEFAULT: usize = 23;

/// The Client Rx MTU we advertise in [`exchange_mtu`], and the size of every ATT
/// response buffer plus the L2CAP reassembly buffer. A negotiated MTU this large
/// lets a full characteristic value arrive in one Read Response, so most
/// device-info strings come back whole. The peer fragments a large response
/// across LL PDUs on air (each ≤ [`CONN_MAX_PAYLOAD`]) and [`Reasm`] rebuilds it,
/// so this bound sizes RAM.
const ATT_MTU_MAX: usize = 247;

/// Most bytes of one characteristic value we accumulate across Read Blob
/// continuations. Bounds the Read Blob fallback that runs when a value exceeds
/// the negotiated MTU.
const ATT_VALUE_CAP: usize = 256;

/// Write `01 00` / `02 00` to each CCCD found on a characteristic that declares
/// notify (0x10) or indicate (0x20), then listen.
///
/// This writes to the peer, unlike the rest of the walk which only reads. It is
/// the ordinary way a GATT client subscribes and it is not persistent: a CCCD
/// written by an unbonded client is reset when the link drops.
const SUBSCRIBE: bool = true;

/// Connection events to hold the link open after enumeration, collecting
/// whatever the subscriptions push. 64 × 31.25 ms = 2 s.
const LISTEN_EVENTS: u32 = 64;

/// Diagnostic: when non-zero, skip enumeration and instead spend this many ms
/// after the `CONNECT_IND` counting advertisements still coming from the target
/// (see [`peer_readv_count`]). 0 = normal operation. Set this when connections
/// form but no peer data ever arrives — it separates "the peer never accepted
/// the CONNECT_IND" from "the link formed but our event timing is wrong".
const DIAG_READV_MS: u64 = 180;

/// Run that probe in place of a real connection on every Nth attempt (0 = never).
///
/// **Answered — leave at 0.** Across a one-minute capture this reported
/// `advs_in_180ms=0 vs later advs=1 (went quiet then came back)` seven times and
/// never once caught a target still advertising inside the window. Peers do
/// accept our CONNECT_IND; the fault is downstream of it. Kept (not deleted)
/// because it is the only thing that can distinguish those two worlds, and the
/// question recurs every time the CONNECT_IND contents change. Note what it does
/// *not* prove: a peer that accepts and then never hears a master packet also
/// goes quiet for its establishment timeout, so silence confirms acceptance, not
/// a working data channel.
///
/// The probe and a connection attempt both need the radio for the same stretch
/// of time, so they cannot run in the same attempt. Alternating keeps both
/// signals — `conn stats` and `accept probe` — in one capture.
///
/// 180 ms is chosen to sit just inside the peripheral's connection-establishment
/// timeout (6 × 31.25 ms ≈ 187 ms) and to exactly match `scan_probe`'s
/// 3 × [`SCAN_PROBE_DWELL_MS`] listen, so the advert counts before and after are
/// directly comparable.
const ACCEPT_PROBE_EVERY: u32 = 0;

/// Print the `conn stats` line and the per-event [`EvTrace`] table when a
/// connection closes.
///
/// **Answered — leave off.** This table is what showed the peer replying exactly
/// once and never again, which is how the LFCLK drift was found. With the clock
/// fixed a healthy connection produces 24 rows of routine stop-and-wait per peer,
/// which buries the enumeration output it was printed alongside. Turn it back on
/// for any "the link forms and then dies" symptom: the `gap` column separates a
/// real T_IFS reply (~150–450 µs) from the miss timeout (1525 µs), and `sn`/`nesn`
/// show whether the retransmit logic or the peer is at fault.
const DIAG_CONN_TRACE: bool = false;

/// Sweep the [`TURNAROUNDS`] table against the target after a connection where
/// the peer was never heard at all.
///
/// **Answered — leave off.** It settled that the hardware T_IFS turnaround needs
/// the default ramp (`dflt/150` at 3/3, every fast variant marginal or worse) and
/// that configuration is now applied everywhere. It costs four probes of up to
/// [`PROBE_MAX_MS`] each — around four seconds of blocked executor per silent
/// connection — and it re-answers a question that is no longer open. Turn it back
/// on if a `CONNECT_IND` ever stops being accepted after a radio-config change.
const DIAG_TURNAROUND_SWEEP: bool = false;

// ── DMA buffers ───────────────────────────────────────────────────────────────
// LL data PDUs are tiny (≤ 2-byte header + 27-byte payload); 64 bytes is plenty.
const CONN_BUF_LEN: usize = 64;
static RX_BUF: crate::SyncBuf<CONN_BUF_LEN> = crate::SyncBuf::new();
static TX_BUF: crate::SyncBuf<CONN_BUF_LEN> = crate::SyncBuf::new();

/// Largest LL payload the RADIO may DMA into [`RX_BUF`], after the 2-byte LL
/// header. See the `MAXLEN` note in [`configure_conn_radio`].
const CONN_MAX_PAYLOAD: usize = CONN_BUF_LEN - 2;

// ── "Seen recently" tracking ──────────────────────────────────────────────────

/// Cooldown after a peer's database has actually been walked. Long, because a
/// second walk of the same peer returns the same table.
const RECENT_WINDOW_S: u64 = 3600;

/// Cooldown after an *attempt* that produced nothing — the CONNECT_IND was
/// refused, or the link formed and the peer never spoke.
///
/// This must exist and it must be short. Without it (the original behaviour)
/// failures were not recorded at all, and since [`survey`] always picks the
/// strongest advertiser, one nearby peer that will not talk to us was re-chosen
/// every single cycle and starved every other device in the room. Setting it to
/// [`RECENT_WINDOW_S`] instead would be the opposite error: roughly a third of
/// attempts in a capture came back silent for transient reasons — a peer already
/// connected to its phone, a collision on the CONNECT_IND — and banning those
/// for an hour throws away devices that would answer a minute later.
const RETRY_COOLDOWN_S: u64 = 60;

/// Slots in the recent-attempt cache.
///
/// This was 32, which made the hour-long window a fiction. Cycles run about 3 s,
/// so 32 slots of distinct addresses were consumed in roughly 90 seconds and the
/// oldest entry — the one whose hour had barely started — was evicted to make
/// room. The effective window was therefore ~1.5 minutes, and the log showed
/// exactly that: a peer fully enumerated at t=11.9 s was picked again at
/// t=123.6 s. Address rotation makes it worse, since every RPA change consumes
/// another slot for a device already in the table.
///
/// 256 × 24 B = 6 KB. Sized for the churn rather than the device count: peers
/// rotate their RPA every ~15 min, so ~20 devices in range generate ~80 distinct
/// addresses per hour, and the rest is headroom for a crowded room.
const RECENT_SLOTS: usize = 256;

#[derive(Clone, Copy)]
struct RecentEntry {
    used: bool,
    addr: [u8; 6],
    /// When this address becomes eligible again. Storing the deadline rather
    /// than the insertion time lets one table hold both cooldown lengths, and
    /// makes "evict the entry that expires soonest" the natural policy.
    until: Instant,
}

struct RecentCache(UnsafeCell<[RecentEntry; RECENT_SLOTS]>);
unsafe impl Sync for RecentCache {}
static RECENT: RecentCache = RecentCache(UnsafeCell::new(
    [RecentEntry { used: false, addr: [0; 6], until: Instant::from_ticks(0) }; RECENT_SLOTS],
));

/// True if `addr` is still inside its cooldown and should be skipped.
fn recently_enumerated(addr: [u8; 6], now: Instant) -> bool {
    let cache = unsafe { &*RECENT.0.get() };
    cache.iter().any(|e| e.used && e.addr == addr && now < e.until)
}

/// Puts `addr` on cooldown for `window_s` seconds, refreshing an existing slot or
/// evicting whichever entry expires soonest.
fn mark_attempted(addr: [u8; 6], now: Instant, window_s: u64) {
    let cache = unsafe { &mut *RECENT.0.get() };
    let until = now + Duration::from_secs(window_s);
    // Refresh if present. Never shorten an existing deadline: a successful walk
    // followed by a failed retry must not turn the hour back into a minute.
    for e in cache.iter_mut() {
        if e.used && e.addr == addr {
            if until > e.until {
                e.until = until;
            }
            return;
        }
    }
    // Free slot, else the entry closest to expiring.
    let mut victim = 0usize;
    let mut soonest = Instant::MAX;
    for (i, e) in cache.iter().enumerate() {
        if !e.used {
            victim = i;
            break;
        }
        if e.until <= soonest {
            soonest = e.until;
            victim = i;
        }
    }
    cache[victim] = RecentEntry { used: true, addr, until };
}

// ── Survey: pick the strongest eligible target ────────────────────────────────

const ADV_CHANNELS: [(u8, u8); 3] = [(37, 2), (38, 26), (39, 80)];
const SURVEY_DWELL_MS: u64 = 60; // per channel; three channels ≈ 180 ms
const SURVEY_ROUNDS: u32 = 3;

#[derive(Clone, Copy)]
struct Candidate {
    addr: [u8; 6],
    addr_random: bool,
    rssi: i16,
}

/// Dwell on the primary advertising channels collecting connectable advertisers
/// (`ADV_IND` / `ADV_DIRECT_IND`), tracking the strongest RSSI per address.
/// Returns the strongest candidate not enumerated within the last hour, if any,
/// along with how many connectable advertisements were heard in total —
/// including from peers the recent-enumeration filter rejected.
async fn survey(rng: &mut Rng) -> (Option<Candidate>, u32) {
    radio_configure_ble(); // advertising AA/CRC
    let r = pac::RADIO;

    let mut best: Option<Candidate> = None;
    let mut connectable = 0u32;
    for _ in 0..SURVEY_ROUNDS {
        for &(ch_idx, freq) in ADV_CHANNELS.iter() {
            radio_ensure_disabled();
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

            let dwell = Duration::from_millis(SURVEY_DWELL_MS);
            let deadline = Instant::now() + dwell;
            while Instant::now() < deadline {
                if r.events_end().read() != 0 {
                    r.events_end().write_value(0);
                    let crc_ok = r.events_crcok().read() != 0;
                    let rssi = -(r.rssisample().read().rssisample() as i16);
                    // EVENTS_CRCOK and EVENTS_ADDRESS are latches: the radio sets
                    // them and never auto-clears. Cleared once before the dwell,
                    // they would then read set for every later reception in it —
                    // including CRC failures — so a corrupt packet's garbage AdvA
                    // would present as a strong connectable advert and win the
                    // survey. Clear both per reception, as `conn_follow` does.
                    r.events_crcok().write_value(0);
                    r.events_address().write_value(0);
                    if crc_ok {
                        let buf = unsafe { &*RX_BUF.0.get() };
                        let pdu_type = buf[0] & 0x0F;
                        // 8-bit Length field (BLE 5 / LFLEN=8).
                        let len = buf[1] as usize;
                        // Connectable, undirected/directed, with an AdvA present.
                        if matches!(pdu_type, 0x00 | 0x01) && len >= 6 {
                            let addr = [buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
                            let addr_random = (buf[0] >> 6) & 1 == 1;
                            connectable += 1;
                            record_candidate(&mut best, addr, addr_random, rssi);
                        }
                    }
                    // Re-arm reception on the same channel for the rest of the dwell.
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
    (best, connectable)
}

/// Keep the strongest connectable advertiser that has not been enumerated within
/// the last hour.
fn record_candidate(best: &mut Option<Candidate>, addr: [u8; 6], addr_random: bool, rssi: i16) {
    // RSSI first, cache second. This runs from inside the survey's busy-poll
    // loop, between packet receptions, and `recently_enumerated` is a linear
    // scan of RECENT_SLOTS — at 256 slots that is long enough to miss the next
    // advertisement. Only a candidate that would actually win is worth the
    // scan, which reduces it to a handful of lookups per survey. The outcome is
    // unchanged: a recently-attempted peer still loses, and a weaker eligible
    // one can still be recorded behind it.
    if let Some(b) = best
        && b.rssi >= rssi
    {
        return;
    }
    if recently_enumerated(addr, Instant::now()) {
        return;
    }
    *best = Some(Candidate { addr, addr_random, rssi });
}

/// Whether this connection attempt should be spent on the accept probe rather
/// than on a real connection. Every [`ACCEPT_PROBE_EVERY`]th attempt, so one
/// capture carries both `conn stats` and `accept probe` lines.
fn accept_probe_round() -> bool {
    use core::sync::atomic::{AtomicU32, Ordering};
    static ATTEMPT: AtomicU32 = AtomicU32::new(0);
    if ACCEPT_PROBE_EVERY == 0 || DIAG_READV_MS == 0 {
        return false;
    }
    let n = ATTEMPT.fetch_add(1, Ordering::Relaxed);
    n % ACCEPT_PROBE_EVERY == ACCEPT_PROBE_EVERY - 1
}

/// DIAGNOSTIC: after a CONNECT_IND, listen ~`window_ms` on the advertising
/// channels and count how many ADVs from `cand.addr` we hear. A peer that
/// *accepted* the CONNECT_IND stops advertising and waits for the master until
/// its establishment timeout expires (6 connection intervals ≈ 187 ms at our
/// 31.25 ms interval) → count should be 0. A peer that *ignored* it keeps
/// advertising → count > 0. Distinguishes "CONNECT_IND not accepted" from
/// "connection formed but data exchange fails".
///
/// `window_ms` must stay under that 187 ms or the two cases converge. Callers
/// should pair the result with a later [`scan_probe`] of the same target —
/// see the call site in [`run`].
async fn peer_readv_count(cand: &Candidate, window_ms: u64) -> u32 {
    radio_configure_ble(); // back to advertising AA/CRC
    let r = pac::RADIO;
    let mut count = 0u32;
    let per_ch = window_ms / (ADV_CHANNELS.len() as u64);
    for &(ch_idx, freq) in ADV_CHANNELS.iter() {
        radio_ensure_disabled();
        r.frequency().write(|w| {
            w.set_frequency(freq);
            w.set_map(vals::Map::Default);
        });
        r.datawhiteiv().write(|w| w.set_datawhiteiv(ch_idx));
        r.packetptr().write_value(RX_BUF.0.get() as u32);
        r.events_end().write_value(0);
        r.events_crcok().write_value(0);
        r.shorts().write(|w| {
            w.set_rxready_start(true);
            w.set_address_rssistart(true);
        });
        r.tasks_rxen().write_value(1);

        let deadline = Instant::now() + Duration::from_millis(per_ch);
        while Instant::now() < deadline {
            if r.events_end().read() != 0 {
                r.events_end().write_value(0);
                if r.events_crcok().read() != 0 {
                    r.events_crcok().write_value(0);
                    let buf = unsafe { &*RX_BUF.0.get() };
                    let addr = [buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
                    if addr == cand.addr {
                        count += 1;
                    }
                }
                r.tasks_start().write_value(1); // re-arm on same channel
            }
            Timer::after_micros(200).await;
        }
        r.shorts().write(|_w| {});
        r.tasks_disable().write_value(1);
        while r.events_disabled().read() == 0 {}
        r.events_disabled().write_value(0);
    }
    count
}

// ── SCAN_REQ probe (diagnostic) ───────────────────────────────────────────────

const SCAN_PROBE_DWELL_MS: u64 = 60; // per advertising channel, per pass
/// Attempts to collect per turnaround config before reporting. Enough that a
/// one-lucky-reply row cannot outrank a genuinely working one.
const PROBE_ATTEMPTS: u32 = 10;
/// Cap on one config's collection, for a target that advertises slowly or leaves.
///
/// This is also a USB deadline, not just a patience limit. [`scan_probe`] is
/// synchronous — it blocks the executor outright — so this bounds how long the
/// CDC logger goes unserviced. Four configs at the 3 s this started out as was
/// 12 s of dead USB in one stretch, well past the host's control-transfer
/// timeout. Keep it under a second and yield between configs.
const PROBE_MAX_MS: u64 = 900;

/// One (ramp-up, TIFS) combination for the turnaround sweep.
#[derive(Clone, Copy)]
struct Turnaround {
    fast_ru: bool,
    tifs_us: u16,
    name: &'static str,
}

/// Candidate turnaround configurations, measured against a real peer.
///
/// The nRF52840 only *qualifies* hardware TIFS with the **default** ramp-up
/// (PS v1.11, RADIO chapter): with `MODECNF0.RU = Fast` the TIFS counter is not
/// corrected for the shorter ramp, so READY — and with it the first bit
/// transmitted, or the start of address search on the receive side — lands off
/// by roughly the difference between the two ramp times. TIFS is timed from the
/// last bit on air to just after READY, which is exactly the interval the ramp
/// length changes.
///
/// The datasheet says the timing is wrong but not by how much or in which
/// direction, and a 40 µs error either way is the difference between hitting the
/// reply's preamble and missing the whole access address. So measure it rather
/// than infer it — `SCAN_REQ`→`SCAN_RSP` exercises this exact turnaround against
/// a reply the peer is obliged to send.
///
/// **Settled, 2026-07-29.** Aggregated over 27 sweeps against 27 different
/// peers: `dflt/150` 8/11 replies, `fast/110` 7/26, `fast/150` 4/22,
/// `fast/190` 1/19. `dflt/150` is now the configuration in [`try_connect`],
/// [`configure_conn_radio`] and the passive follower. The sweep stays because
/// it is the cheapest way to tell "the turnaround regressed" from "this peer
/// just would not talk", and it only runs when a connection saw `addr=0`.
///
/// `dflt/150` collects fewer `advs` per sweep than the fast rows — a 140 µs RX
/// ramp misses more adverts while re-arming. That depresses its sample size,
/// not its hit *rate*, which is what the comparison uses.
const TURNAROUNDS: [Turnaround; 4] = [
    Turnaround { fast_ru: false, tifs_us: 150, name: "dflt/150 current" },
    Turnaround { fast_ru: true, tifs_us: 150, name: "fast/150" },
    Turnaround { fast_ru: true, tifs_us: 190, name: "fast/190 +40" },
    Turnaround { fast_ru: true, tifs_us: 110, name: "fast/110 -40" },
];

/// Where a [`scan_probe`] attempt got to. Reported as a whole so a zero response
/// count can be attributed rather than guessed at.
#[derive(Default)]
struct ProbeStats {
    /// Scannable adverts matched from the target — attempts made.
    advs: u32,
    /// …that reached TXREADY, i.e. the turnaround actually ramped the transmitter.
    txready: u32,
    /// …whose SCAN_REQ finished going out.
    txend: u32,
    /// …where the receive half then matched an access address. This is the
    /// measurement that matters for a mistimed turnaround: ADDRESS fires only if
    /// the receiver was already on air and searching when the reply's preamble
    /// arrived, so `rxaddr=0` means we came up outside the reply entirely, while
    /// `rxaddr>0` with `rsp=0` means the timing is right and something else
    /// (whitening, CRC, the peer answering someone else) is wrong.
    rxaddr: u32,
    /// …that produced a second END, i.e. a whole packet was clocked in.
    rxend: u32,
    /// …answered by a valid SCAN_RSP from the target.
    rsp: u32,
    /// RADIO.STATE sampled on entry to the first attempt. 4 (RxDisable) or 9
    /// (TxRu) means we reacted inside the turnaround; 0/10 means we arrived after
    /// it had already run and the attempt was never valid.
    state0: u32,
}

/// DIAGNOSTIC: fires a `SCAN_REQ` at `cand` and waits for the `SCAN_RSP`.
///
/// **Synchronous on purpose.** The turnaround transmits 150 µs after the advert
/// ends and the whole exchange is over in ~700 µs, so the receive half has to be
/// staged within that window. An `await` here — even `yield_now` — hands the
/// executor to the USB logger and can cost hundreds of µs, long enough to arrive
/// after our own SCAN_REQ has already been sent, at which point the attempt
/// silently measures nothing. Blocking the executor for the probe's ~180 ms is
/// the cheaper trade; the log channel is 32 deep and absorbs it.
///
/// This exercises the two turnarounds a connection depends on — the hardware
/// RX→TX at T_IFS that transmits the CONNECT_IND, and the TX→RX return that a
/// connection event uses to hear the peer — but against a reply the peer is
/// *obliged* to send. That is what the connection itself can never tell us:
/// "our transmitter is broken" and "the peer refused us" both look exactly like
/// silence. A `SCAN_RSP` coming back proves the radio path is sound and moves
/// the fault onto the CONNECT_IND's content or the peer's acceptance policy;
/// no `SCAN_RSP` despite matched adverts means we are not getting on air at all.
fn scan_probe(cand: &Candidate, t: Turnaround) -> ProbeStats {
    radio_configure_ble();
    let r = pac::RADIO;
    r.tifs().write(|w| w.set_tifs(t.tifs_us));
    r.modecnf0().modify(|w| {
        w.set_ru(if t.fast_ru { vals::Ru::Fast } else { vals::Ru::Default })
    });

    // SCAN_REQ: type 0x03, TxAdd = ours (random static), RxAdd = target's;
    // 12-byte payload = ScanA + AdvA.
    {
        let buf = unsafe { &mut *TX_BUF.0.get() };
        buf[0] = 0x03 | (1 << 6) | ((cand.addr_random as u8) << 7);
        buf[1] = 12;
        buf[2..8].copy_from_slice(&our_addr());
        buf[8..14].copy_from_slice(&cand.addr);
    }

    // Collect a fixed number of *attempts*, not a fixed span of time. A
    // time-boxed probe measures how often the target happened to advertise, not
    // how often the turnaround worked: the first version of this sweep returned
    // `advs=0` or `advs=1` on nearly every row, so a config that answered once
    // out of one attempt was indistinguishable from one that answered twice out
    // of five. Equal `advs` across rows is what makes the `rsp` column
    // comparable. `PROBE_MAX_MS` bounds a slow or departed advertiser.
    let mut st = ProbeStats::default();
    let give_up = Instant::now() + Duration::from_millis(PROBE_MAX_MS);
    'collect: while st.advs < PROBE_ATTEMPTS && Instant::now() < give_up {
        for &(ch_idx, freq) in ADV_CHANNELS.iter() {
            arm_connect_rx(ch_idx, freq);
            let deadline = Instant::now() + Duration::from_millis(SCAN_PROBE_DWELL_MS);
            while Instant::now() < deadline {
                if r.events_end().read() == 0 {
                    continue; // tight poll — see the note on reaction time above
                }
                r.events_end().write_value(0);
                // Scannable advert from the target? (ADV_IND / ADV_SCAN_IND)
                let buf = unsafe { &*RX_BUF.0.get() };
                let hit = r.events_crcok().read() != 0
                    && matches!(buf[0] & 0x0F, 0x00 | 0x06)
                    && buf[2..8] == cand.addr;
                if hit {
                    if st.advs == 0 {
                        st.state0 = r.state().read().0;
                    }
                    st.advs += 1;
                    await_scan_rsp(cand, &mut st);
                    if st.advs >= PROBE_ATTEMPTS {
                        radio_disable_silent();
                        break 'collect;
                    }
                }
                radio_disable_silent();
                if Instant::now() >= deadline {
                    break;
                }
                arm_connect_rx(ch_idx, freq);
            }
            radio_disable_silent();
            if Instant::now() >= give_up {
                break 'collect;
            }
        }
    }
    st
}

/// Second half of [`scan_probe`], from the moment a target advert has been
/// matched: stage the receive half of the turnaround, then wait for the reply.
/// Records how far the attempt got in `st`.
fn await_scan_rsp(cand: &Candidate, st: &mut ProbeStats) {
    let r = pac::RADIO;
    // Wait for TXREADY. By the time we observe it the `txready_start` short has
    // already fired, so TX_BUF is latched and PACKETPTR is free to be repointed
    // at RX_BUF for the *next* transfer — the peer's reply.
    let ready_by = Instant::now() + Duration::from_micros(400);
    while r.events_ready().read() == 0 {
        if Instant::now() >= ready_by {
            return;
        }
    }
    st.txready += 1;
    r.events_ready().write_value(0);
    r.packetptr().write_value(RX_BUF.0.get() as u32);
    // Swap the chain around: this time DISABLED must ramp the *receiver*, and
    // TIFS is still 150 so the hardware puts us back on air exactly T_IFS after
    // our SCAN_REQ ends — the same gap the peer is timing its reply to.
    r.shorts().write(|w| {
        w.set_end_disable(true);
        w.set_disabled_rxen(true);
        w.set_rxready_start(true);
        w.set_address_rssistart(true);
    });
    r.events_end().write_value(0);
    r.events_crcok().write_value(0);

    // First END is our SCAN_REQ leaving the antenna…
    let tx_by = Instant::now() + Duration::from_micros(600);
    while r.events_end().read() == 0 {
        if Instant::now() >= tx_by {
            return;
        }
    }
    st.txend += 1;
    r.events_end().write_value(0);
    r.events_address().write_value(0);
    // …the second is the peer's SCAN_RSP. T_IFS (150 µs) + a max-length response
    // (376 µs) fits comfortably in 1 ms.
    let rx_by = Instant::now() + Duration::from_micros(1000);
    while r.events_end().read() == 0 {
        if Instant::now() >= rx_by {
            // Nothing completed. ADDRESS still tells us whether the receiver was
            // even in the right place — sampled here because `radio_disable_silent`
            // in the caller is about to clear it.
            if r.events_address().read() != 0 {
                st.rxaddr += 1;
            }
            return;
        }
    }
    st.rxend += 1;
    if r.events_address().read() != 0 {
        st.rxaddr += 1;
    }
    if r.events_crcok().read() == 0 {
        return;
    }
    let buf = unsafe { &*RX_BUF.0.get() };
    if (buf[0] & 0x0F) == 0x04 && buf[2..8] == cand.addr {
        st.rsp += 1;
    }
}

// ── CONNECT_IND assembly ──────────────────────────────────────────────────────

/// Fills [`TX_BUF`] with a `CONNECT_IND` PDU targeting `cand`. Assembled once
/// before arming the reception so the hardware RX→TX turnaround can fire it with
/// no software in the critical path.
fn build_connect_ind(cand: &Candidate) {
    let buf = unsafe { &mut *TX_BUF.0.get() };
    // Header: type=0x05 (CONNECT_IND); TxAdd (bit6)=our addr type (random=1);
    // RxAdd (bit7)=target addr type; ChSel (bit5)=0 → CSA#1.
    let tx_add = 1u8; // our address is random static
    let rx_add = cand.addr_random as u8;
    buf[0] = 0x05 | (tx_add << 6) | (rx_add << 7);
    buf[1] = 34; // 6 (InitA) + 6 (AdvA) + 22 (LLData)
    buf[2..8].copy_from_slice(&our_addr()); // InitA (LE, on-air order)
    buf[8..14].copy_from_slice(&cand.addr); // AdvA (LE, as received)

    let ll = &mut buf[14..36];
    ll[0..4].copy_from_slice(&conn_aa().to_le_bytes());
    ll[4..7].copy_from_slice(&conn_crc_init().to_le_bytes()[0..3]);
    ll[7] = WIN_SIZE;
    ll[8..10].copy_from_slice(&WIN_OFFSET.to_le_bytes());
    ll[10..12].copy_from_slice(&CONN_INTERVAL.to_le_bytes());
    ll[12..14].copy_from_slice(&CONN_LATENCY.to_le_bytes());
    ll[14..16].copy_from_slice(&CONN_TIMEOUT.to_le_bytes());
    // Channel map: all 37 data channels usable (bits 0..36) → FF FF FF FF 1F.
    ll[16..21].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1F]);
    // Hop (bits 0..4) + SCA (bits 5..7, 0 = worst-case, fine as master).
    ll[21] = conn_hop() & 0x1F;
}

// ── Connection state ──────────────────────────────────────────────────────────

struct Conn {
    /// Absolute deadline of the next connection event's master transmission.
    anchor: Instant,
    /// CSA#1 last unmapped channel index (0..36).
    unmapped: u8,
    /// Master transmit sequence number (stop-and-wait).
    sn: u8,
    /// Next expected sequence number from the peer.
    nesn: u8,
    /// Diagnostic counters over the connection's lifetime: total events driven,
    /// events where the peer's reply preamble+AA matched (EVENTS_ADDRESS after our
    /// TX), and events where that reply passed CRC (EVENTS_CRCOK). Distinguish
    /// "never hear the peer" (addr=0 → timing/anchor) from "hear but CRC fails"
    /// (addr>0, crcok=0 → whitening/CRCInit) from "receiving OK" (crcok>0).
    ev_total: u32,
    ev_addr: u32,
    ev_crcok: u32,
    /// Events where our master TX completed (EVENTS_DISABLED before the 3 ms
    /// deadline). If this is 0 the radio isn't transmitting at all.
    ev_txdone: u32,
    /// Signed µs by which we entered the *first* conn_event relative to its anchor:
    /// negative = early (good, Timer::at will wait), positive = late (we missed
    /// event 0's transmit window → the peer never anchors). `i32::MIN` = unset.
    first_late_us: i32,
    /// Set once the peer's first CRC-good reply has been logged. Proof the link
    /// is live, printed the moment it happens rather than only in the closing
    /// summary — and the event number it lands on says whether our anchor was
    /// right from the start (ev=1) or we only caught the peer later.
    saw_reply: bool,
    /// Negotiated ATT MTU. Starts at [`ATT_MTU_DEFAULT`]; [`exchange_mtu`] raises
    /// it toward [`ATT_MTU_MAX`] to the smaller of the two peers' Rx MTUs.
    att_mtu: u16,
    /// Ring of the first [`TRACE_EVENTS`] events, dumped after the link ends.
    trace: [EvTrace; TRACE_EVENTS],
}

/// One connection event, recorded to RAM and printed only after the connection
/// is over.
///
/// Logging this inline is not an option: `ulogf!` during an event competes with
/// the tight T_IFS turnaround it is trying to measure, so the instrument changes
/// the reading. 16 bytes × [`TRACE_EVENTS`] of static RAM buys a timing-neutral
/// record.
///
/// What it is for: connections now reach `addr=1 crcok=1` — the peer answers
/// exactly once, on the same event where `att_txn` sees its request acked and
/// switches from `stage_att` to `stage_empty`, and never again. That correlation
/// needs the transmitted header and the reply's own header side by side across
/// the transition to resolve.
#[derive(Clone, Copy, Default)]
struct EvTrace {
    /// Data channel index this event hopped to.
    ch: u8,
    /// Byte 0 of what we transmitted: LLID | NESN<<2 | SN<<3.
    tx_hdr: u8,
    /// Payload length we transmitted (TX_BUF[1]).
    tx_len: u8,
    /// Bit 0 = EVENTS_ADDRESS, bit 1 = EVENTS_CRCOK, bit 2 = reply END seen.
    flags: u8,
    /// Byte 0 / byte 1 of the reply, when one arrived.
    rx_hdr: u8,
    rx_len: u8,
    /// TX DISABLED → reply END, µs. With hardware TIFS this should be
    /// 150 + the reply's air time; a wild value means we latched the wrong thing.
    gap_us: u16,
}

/// Events recorded per connection. The interesting window is the first reply
/// (observed at events 1-5) plus enough afterwards to show what the peer stops
/// responding to.
const TRACE_EVENTS: usize = 24;

/// Result of one master TX + peer RX exchange within a connection event.
struct RxPdu {
    llid: u8,
    sn: u8,
    nesn: u8,
    len: u8,
}

/// Arms an RX on `(ch_idx, freq)` with the RX→TX turnaround chain that fires the
/// pre-built `CONNECT_IND` T_IFS after the received packet ends.
///
/// `PACKETPTR` is left at `RX_BUF` so the RX `TASKS_START` — fired by the
/// `rxready_start` short once the ramp completes — latches `RX_BUF` for the
/// incoming advert. EasyDMA reads `PACKETPTR` at `START`, not at `RXEN`, so the
/// pointer must still be `RX_BUF` when that short fires ~140 µs later. The swap
/// to `TX_BUF` for the turnaround is therefore deferred to [`finish_connect`],
/// which repoints it only on a target match, in the T_IFS + ramp gap before the
/// turnaround's TX `START`. Staging `TX_BUF` here instead loses the race: the CPU
/// write beats RXREADY by ~140 µs, so every reception lands in `TX_BUF`, `RX_BUF`
/// never updates, and the address check reads a stale buffer — `target=0` on
/// every attempt.
fn arm_connect_rx(ch_idx: u8, freq: u8) {
    let r = pac::RADIO;
    radio_ensure_disabled();
    r.frequency().write(|w| {
        w.set_frequency(freq);
        w.set_map(vals::Map::Default);
    });
    r.datawhiteiv().write(|w| w.set_datawhiteiv(ch_idx));
    r.packetptr().write_value(RX_BUF.0.get() as u32);
    r.events_end().write_value(0);
    r.events_crcok().write_value(0);
    r.events_address().write_value(0);
    r.events_ready().write_value(0);
    r.events_disabled().write_value(0);
    // RXREADY→START latches RX_BUF for reception the moment the ramp completes.
    // On RX end: disable, TXEN (the radio inserts T_IFS), start.
    //
    // Doing the RX start in hardware rather than busy-waiting on EVENTS_READY
    // matters because `try_connect` re-arms after *every* packet it hears, not
    // just the target's — around 880 of them per attempt — and the default
    // 140 µs ramp it waits through is receiver downtime in a search that only
    // succeeds if it happens to be listening when the target advertises.
    r.shorts().write(|w| {
        w.set_rxready_start(true);
        w.set_end_disable(true);
        w.set_disabled_txen(true);
        w.set_txready_start(true);
        w.set_address_rssistart(true);
    });
    r.tasks_rxen().write_value(1);
}

/// What [`try_connect`] observed while surveying, logged when the attempt fails
/// so the failure mode is readable from one line instead of a reflash.
///
/// Reading it: `target=0` — we never heard the target during any dwell, so it
/// stopped advertising or the survey's idea of its channel/rate is wrong (the
/// candidate came from an earlier scan). `target>0 connectable=0` — it only
/// sends non-connectable adverts and should never have been a candidate.
/// `connectable>0 txfail>0` — we matched it but the hardware T_IFS turnaround
/// never transmitted the CONNECT_IND (ramp-up/SHORTS problem, not a peer
/// problem). `pkts` high with `crcok` near zero — the receiver is misconfigured.
#[derive(Default)]
struct ConnectStats {
    /// Receptions that ended, from any device, CRC good or bad.
    pkts: u32,
    /// …of which passed CRC.
    crcok: u32,
    /// …of which were an advertising PDU carrying the target's AdvA.
    target: u32,
    /// …of which were connectable (`ADV_IND` / `ADV_DIRECT_IND`).
    connectable: u32,
    /// Target matched and the turnaround was left to fire, but the CONNECT_IND
    /// transmission never completed within 2 ms.
    txfail: u32,
}

/// Attempts to open a connection to `cand`: listens for its connectable ADV on
/// the primary channels and fires the pre-built `CONNECT_IND` at T_IFS. Returns
/// the initial [`Conn`] on success (with `anchor` set to the first event), and
/// accumulates what it saw into `st` either way.
async fn try_connect(cand: &Candidate, st: &mut ConnectStats) -> Option<Conn> {
    radio_configure_ble();
    build_connect_ind(cand);
    let r = pac::RADIO;
    r.tifs().write(|w| w.set_tifs(T_IFS_US));
    // Default (140 µs) ramp-up. This looks wrong against a 150 µs T_IFS and an
    // earlier revision used Fast (40 µs) for exactly that reason — but hardware
    // TIFS already accounts for the ramp: it times from the last bit on air to
    // just after READY, and the nRF52840 PS qualifies that only for the default
    // ramp. Fast shifts the turnaround by the ~100 µs ramp difference with no
    // compensation. Measured over 27 SCAN_REQ→SCAN_RSP sweeps (`TURNAROUNDS`):
    // dflt/150 8/11 replies, fast/110 7/26, fast/150 4/22, fast/190 1/19.
    r.modecnf0().modify(|w| w.set_ru(vals::Ru::Default));

    // A few passes over the advertising channels waiting to catch the target.
    for _ in 0..(SURVEY_ROUNDS * 2) {
        for &(ch_idx, freq) in ADV_CHANNELS.iter() {
            arm_connect_rx(ch_idx, freq);

            let deadline = Instant::now() + Duration::from_millis(SURVEY_DWELL_MS);
            while Instant::now() < deadline {
                if r.events_end().read() == 0 {
                    // Tight poll, no yield. Two things depend on reacting inside
                    // T_IFS (150 µs): aborting the turnaround on a non-target
                    // packet, and — on a match — observing TXREADY before the
                    // CONNECT_IND has already been sent and bounced. `yield_now`
                    // hands the executor to the USB logger, which can blow past
                    // both. The cost is that USB drains only between dwells.
                    continue;
                }
                r.events_end().write_value(0);
                st.pkts += 1;
                if let Some(conn) = finish_connect(cand, st) {
                    return Some(conn);
                }
                // Not our target (or bad CRC): the turnaround is already ramping
                // TX. Clear SHORTS before disabling — otherwise the disabled_txen
                // short re-fires TXEN the instant we hit DISABLED and the radio
                // bounces back on, spewing spurious CONNECT_INDs.
                radio_disable_silent();
                // Keep listening on this channel for the rest of the dwell.
                // Bailing to the next channel here (the previous behaviour) made
                // each dwell end at the *first* packet from anyone, so the whole
                // 18-dwell search collapsed to ~20 ms and only ever connected
                // when the target's advert happened to be the first one heard.
                if Instant::now() >= deadline {
                    break;
                }
                arm_connect_rx(ch_idx, freq);
            }

            // End of dwell: the radio is still armed in RX with the turnaround
            // shorts set. Clear shorts + disable silently so it can't bounce back
            // on before we re-arm the next channel.
            radio_disable_silent();
        }
    }
    None
}

/// Called the instant an armed reception ends: if the received PDU is our target,
/// let the hardware turnaround transmit the CONNECT_IND and build the [`Conn`];
/// otherwise return `None` so the caller aborts the pending transmission.
fn finish_connect(cand: &Candidate, st: &mut ConnectStats) -> Option<Conn> {
    let r = pac::RADIO;
    if r.events_crcok().read() == 0 {
        return None;
    }
    st.crcok += 1;
    let buf = unsafe { &*RX_BUF.0.get() };
    let pdu_type = buf[0] & 0x0F;
    // Address match first, so a target advert that is merely *not connectable*
    // is still counted as "heard" — that distinction is the whole point of the
    // stats line. AdvA sits at [2..8] only for the advertising PDUs below;
    // SCAN_REQ/CONNECT_IND put the initiator's address there instead, so they
    // are excluded rather than mis-attributed.
    if !matches!(pdu_type, 0x00 | 0x01 | 0x02 | 0x04 | 0x06) {
        return None;
    }
    let addr = [buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
    if addr != cand.addr {
        return None;
    }
    st.target += 1;
    if !matches!(pdu_type, 0x00 | 0x01) {
        return None;
    }
    st.connectable += 1;

    // The advert landed in RX_BUF (latched at the RX START). Repoint PACKETPTR at
    // the staged CONNECT_IND now, in the T_IFS + TX-ramp gap before the
    // turnaround's TX START latches it, so the shorts chain sends CONNECT_IND at
    // T_IFS. Deferring the swap to here — rather than staging it in
    // `arm_connect_rx` — is what keeps the reception in RX_BUF; it also means a
    // non-target's aborted turnaround can only emit harmless RX_BUF garbage,
    // never a CONNECT_IND aimed at the wrong device.
    r.packetptr().write_value(TX_BUF.0.get() as u32);

    // Disarm `disabled_txen` the moment TXREADY says the turnaround has
    // committed to transmitting. Left armed it bounces the radio
    // END → DISABLED → TXEN → START → … , re-sending the CONNECT_IND every
    // ~500 µs; then if we are even slightly late reading EVENTS_END below we
    // clear the *real* TX END and end up timestamping a retransmission, so
    // `connect_end` — and with it every anchor derived from it — is off by a
    // whole bounce period while the peer anchored on the first copy it heard.
    // Clearing shorts here is safe: TXREADY and the TXREADY→START short fire on
    // the same edge, so START has already been triggered.
    r.events_ready().write_value(0);
    let ready_by = Instant::now() + Duration::from_micros(400);
    while r.events_ready().read() == 0 {
        if Instant::now() >= ready_by {
            st.txfail += 1; // turnaround never ramped TX
            return None;
        }
    }
    r.shorts().write(|w| w.set_end_disable(true));

    // Wait for that single TX to complete and timestamp its end — the
    // connection timeline anchors on it.
    r.events_end().write_value(0);
    r.events_disabled().write_value(0);
    let tx_deadline = Instant::now() + Duration::from_millis(2);
    while r.events_end().read() == 0 {
        if Instant::now() >= tx_deadline {
            st.txfail += 1; // ramped but never got the packet out
            return None;
        }
    }
    let connect_end = Instant::now();
    r.events_end().write_value(0);
    // Settle the radio in DISABLED before configure_conn_radio() runs, or it
    // finds the radio still running and logs a spurious radio_stuck.
    radio_disable_silent();

    ulogf!(
        "CONNECT_IND -> {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} rssi={} aa={:08X}\r\n",
        cand.addr[5], cand.addr[4], cand.addr[3], cand.addr[2], cand.addr[1], cand.addr[0],
        cand.rssi, conn_aa()
    );

    // First anchor = connIndEnd + transmitWindowDelay + WinOffset·1.25 ms.
    let anchor = connect_end
        + Duration::from_micros(TX_WIN_DELAY_US + WIN_OFFSET as u64 * 1250);
    Some(Conn {
        anchor,
        unmapped: 0,
        sn: 0,
        nesn: 0,
        ev_total: 0,
        ev_addr: 0,
        ev_crcok: 0,
        ev_txdone: 0,
        trace: [EvTrace::default(); TRACE_EVENTS],
        first_late_us: i32::MIN,
        saw_reply: false,
        att_mtu: ATT_MTU_DEFAULT as u16,
    })
}

// ── Connection radio config & per-event exchange ──────────────────────────────

/// Switches the RADIO to this connection's access address / CRC init. Whitening
/// IV and frequency are set per event as we hop.
fn configure_conn_radio() {
    let r = pac::RADIO;
    radio_ensure_disabled();
    r.mode().write(|w| w.set_mode(vals::Mode::Ble1mbit));
    set_pcnf0(vals::Plen::_8bit);
    set_access_address(conn_aa());
    r.crcpoly().write(|w| w.set_crcpoly(ADV_CRC_POLY));
    r.crcinit().write(|w| w.set_crcinit(conn_crc_init()));
    // `radio_configure_ble` leaves MAXLEN at 255 so that large AUX_ADV_IND
    // payloads survive aux following, but the connection buffers are only
    // CONN_BUF_LEN bytes. EasyDMA honours MAXLEN, not the buffer, so a length
    // byte corrupted on air — or a peer that simply sends more than we asked
    // for — would have the RADIO write past RX_BUF into whatever follows it in
    // .bss. Cap it at what the buffer can actually hold; anything longer is
    // truncated by the hardware (and fails CRC, so it is discarded anyway).
    r.pcnf1().modify(|w| w.set_maxlen(CONN_MAX_PAYLOAD as u8));
    // Hardware inter-frame spacing, same as the advertising-channel turnaround.
    // `conn_event` lets the shorts chain place the receiver so it comes on air
    // exactly T_IFS after our packet ends. An earlier revision set TIFS=0 and
    // drove RXEN from software on the theory that listening *early and wide*
    // was more forgiving; on hardware that variant never produced a single
    // EVENTS_ADDRESS in 40 events, while the SCAN_REQ→SCAN_RSP probe — which
    // uses the hardware chain — does get replies from real peers. Trust the
    // measurement.
    r.tifs().write(|w| w.set_tifs(T_IFS_US));
    // Default (140 µs) ramp-up — the configuration hardware TIFS is qualified
    // for. See the note in `try_connect`; Fast ramp here is what produced
    // `addr=0` on 40 of 40 connection events.
    r.modecnf0().modify(|w| w.set_ru(vals::Ru::Default));
}

/// Runs one connection event: waits for the anchor, hops (CSA#1), transmits the
/// PDU currently staged in [`TX_BUF`] (`tx_len` payload bytes), and receives the
/// peer's reply via the hardware T_IFS turnaround. Advances `anchor` by one
/// interval. Returns the peer PDU descriptor, or `None` if the peer did not
/// answer. The received payload (if any) lands in `RX_BUF[2..]`.
async fn conn_event(conn: &mut Conn, tx_len: u8) -> Option<RxPdu> {
    // Diagnostic: how close to the first anchor did we actually arrive? If we're
    // already past it, Timer::at returns immediately and event 0 fires late,
    // outside the peer's transmit window → the peer never anchors.
    if conn.first_late_us == i32::MIN {
        let now = Instant::now();
        conn.first_late_us = match conn.anchor.checked_duration_since(now) {
            Some(d) => -(d.as_micros() as i32), // early: negative
            None => now.duration_since(conn.anchor).as_micros() as i32, // late: positive
        };
    }
    Timer::at(conn.anchor).await;
    conn.anchor += Duration::from_ticks(CONN_INTERVAL_TICKS);

    // CSA#1: next data channel = (last + hop) mod 37 (full map → no remap).
    conn.unmapped = (conn.unmapped + conn_hop()) % 37;
    let freq = match data_ch_freq(conn.unmapped) {
        Some(f) => f,
        None => return None,
    };

    let r = pac::RADIO;
    radio_ensure_disabled();
    r.frequency().write(|w| {
        w.set_frequency(freq);
        w.set_map(vals::Map::Default);
    });
    r.datawhiteiv().write(|w| w.set_datawhiteiv(conn.unmapped));
    r.packetptr().write_value(TX_BUF.0.get() as u32);
    let _ = tx_len; // header already carries the length (TX_BUF[1])

    conn.ev_total += 1;
    r.events_end().write_value(0);
    r.events_disabled().write_value(0);
    r.events_crcok().write_value(0);
    r.events_address().write_value(0);
    r.events_ready().write_value(0);
    // One unbroken hardware chain: TXEN → (fast ramp) → START → our PDU → END
    // → DISABLE → DISABLED → RXEN → (T_IFS) → RXREADY → START. The receiver
    // therefore comes on air exactly T_IFS after our packet ends, which is when
    // the peer starts transmitting. This is the same turnaround `scan_probe`
    // uses to collect SCAN_RSPs off real peers, so it is known-good on this
    // radio; software-driven RXEN is not.
    r.shorts().write(|w| {
        w.set_txready_start(true);
        w.set_end_disable(true);
        w.set_disabled_rxen(true);
        w.set_rxready_start(true);
        w.set_address_rssistart(true);
    });
    r.tasks_txen().write_value(1);

    // TXREADY: START has already latched TX_BUF, so PACKETPTR can be re-aimed at
    // RX_BUF for the reply the same chain is about to receive.
    let ready_by = Instant::now() + Duration::from_micros(400);
    while r.events_ready().read() == 0 {
        if Instant::now() >= ready_by {
            cleanup_radio();
            return None;
        }
    }
    r.events_ready().write_value(0);
    r.packetptr().write_value(RX_BUF.0.get() as u32);

    // Our PDU goes out and the radio disables itself.
    let tx_deadline = Instant::now() + Duration::from_micros(1000);
    while r.events_disabled().read() == 0 {
        if Instant::now() >= tx_deadline {
            cleanup_radio();
            return None;
        }
    }
    conn.ev_txdone += 1;
    r.events_disabled().write_value(0);
    // DISABLED has fired, so `disabled_rxen` has already armed the receiver.
    // Drop it now, otherwise the chain re-arms RX after the peer's reply and the
    // next reception overwrites RX_BUF before we read it. `rxready_start` must
    // stay: TIFS holds RXREADY off until T_IFS after our packet ended, well
    // after this point.
    r.shorts().write(|w| {
        w.set_end_disable(true);
        w.set_rxready_start(true);
        w.set_address_rssistart(true);
    });
    // Our own TX set EVENTS_END; clear it (and the reception flags) so the wait
    // below sees only the peer's packet. Safe here — the reply cannot end before
    // T_IFS + preamble, ~160 µs away.
    r.events_end().write_value(0);
    r.events_address().write_value(0);
    r.events_crcok().write_value(0);

    // Await the peer's reply. A wide window covers ramp + T_IFS + the largest reply.
    let tx_done_at = Instant::now();
    let rx_deadline = tx_done_at + Duration::from_micros(1500);
    let mut got = false;
    while Instant::now() < rx_deadline {
        if r.events_end().read() != 0 {
            r.events_end().write_value(0);
            got = true;
            break;
        }
    }
    let gap_us = Instant::now().duration_since(tx_done_at).as_micros().min(0xFFFF) as u16;
    // Diagnostic: did the peer's reply even begin (AA match) / pass CRC? Read
    // before cleanup_radio clears the events.
    let addr_seen = r.events_address().read() != 0;
    let crc_seen = r.events_crcok().read() != 0;
    if addr_seen {
        conn.ev_addr += 1;
    }
    if crc_seen {
        conn.ev_crcok += 1;
    }
    cleanup_radio();

    // One colour per connection event, held until the next one replaces it.
    // Signalling both a "transmitting" and a "received" colour within the same
    // event would show neither: `led::LED` is a Signal, and this function never
    // yields between the two points, so the LED task would only ever observe
    // the second. At one event per 31.25 ms the distinction that is actually
    // visible — and useful — is whether the peer answered.
    // Red only for a reply we could actually use: a CRC failure is discarded
    // below, so showing it as a good event would hide the one condition this
    // indicator exists to make visible.
    led::solid(if got && crc_seen { led::RED } else { led::BLUE });

    // Record before the early return, so a silent event is traced too — the
    // silence is the symptom being investigated.
    if let Some(t) = conn.trace.get_mut(conn.ev_total as usize - 1) {
        let rxb = unsafe { &*RX_BUF.0.get() };
        *t = EvTrace {
            ch: conn.unmapped,
            tx_hdr: unsafe { (*TX_BUF.0.get())[0] },
            tx_len: unsafe { (*TX_BUF.0.get())[1] },
            flags: (addr_seen as u8) | ((crc_seen as u8) << 1) | ((got as u8) << 2),
            rx_hdr: if got { rxb[0] } else { 0 },
            rx_len: if got { rxb[1] } else { 0 },
            gap_us,
        };
    }

    if !got {
        return None;
    }

    // A packet that demodulated but failed CRC must be treated exactly like
    // silence. EVENTS_END fires at the end of *any* reception, so gating only on
    // `got` handed corrupt bytes to `update_flow` — advancing SN/NESN off a
    // garbage header, which acks data we never received and desyncs the link —
    // and to the L2CAP parser, where a corrupted length byte surfaced as
    // `peer L2CAP frame too large (3590 B)`. The bad frame is the visible
    // symptom; the flow-control corruption is the damage.
    if !crc_seen {
        // Discard corrupt receptions silently. Acting on a CRC failure would
        // advance SN/NESN off a garbage header (desyncing flow control) and hand a
        // bad length to the L2CAP parser; the `return None` is what prevents that.
        // GATT mode (active central) does not log the corrupt bytes — it wants the
        // clean exchange, not the noise the passive conn-follow salvage path keeps.
        return None;
    }

    let buf = unsafe { &*RX_BUF.0.get() };
    let hdr = buf[0];
    let pdu = RxPdu {
        llid: hdr & 0x03,
        sn: (hdr >> 3) & 1,
        nesn: (hdr >> 2) & 1,
        // Clamped so a length that outran the buffer can never panic the slice
        // in the callers. With MAXLEN set this should be unreachable; it costs
        // nothing to make it structurally impossible rather than configurable.
        len: buf[1].min(CONN_MAX_PAYLOAD as u8),
    };
    if !conn.saw_reply && conn.ev_crcok > 0 {
        conn.saw_reply = true;
        ulogf!(
            "link live: peer replied on ev={} llid={} len={} ch={}\r\n",
            conn.ev_total, pdu.llid, pdu.len, conn.unmapped
        );
    }
    Some(pdu)
}

fn cleanup_radio() {
    let r = pac::RADIO;
    r.shorts().write(|_w| {});
    r.tasks_disable().write_value(1);
    while r.events_disabled().read() == 0 {}
    r.events_disabled().write_value(0);
}

// ── LL/L2CAP TX staging ───────────────────────────────────────────────────────

/// Stages an empty LL data PDU (LLID=01, len=0) with the current SN/NESN.
fn stage_empty(conn: &Conn) -> u8 {
    let buf = unsafe { &mut *TX_BUF.0.get() };
    buf[0] = 0b01 | (conn.nesn << 2) | (conn.sn << 3);
    buf[1] = 0;
    0
}

/// Stages an ATT request as an L2CAP frame on CID 0x0004 in one LL data PDU
/// (LLID=10, start of an L2CAP message). Returns the LL payload length.
fn stage_att(conn: &Conn, att: &[u8]) -> u8 {
    let buf = unsafe { &mut *TX_BUF.0.get() };
    let l2_len = att.len() as u16;
    let payload_len = 4 + att.len();
    buf[0] = 0b10 | (conn.nesn << 2) | (conn.sn << 3);
    buf[1] = payload_len as u8;
    buf[2..4].copy_from_slice(&l2_len.to_le_bytes());
    buf[4..6].copy_from_slice(&0x0004u16.to_le_bytes()); // ATT CID
    buf[6..6 + att.len()].copy_from_slice(att);
    payload_len as u8
}

/// Applies stop-and-wait flow control given the peer's PDU. Returns
/// `(new_data, acked)`: whether the peer sent fresh data (advancing our NESN) and
/// whether the peer acknowledged our last transmission (advancing our SN).
fn update_flow(conn: &mut Conn, rx: &RxPdu) -> (bool, bool) {
    let new_data = rx.sn == conn.nesn;
    if new_data {
        conn.nesn ^= 1;
    }
    let acked = rx.nesn != conn.sn;
    if acked {
        conn.sn ^= 1;
    }
    (new_data, acked)
}

// ── L2CAP reassembly ──────────────────────────────────────────────────────────

/// Largest L2CAP frame we will reassemble. Holds an ATT PDU of the full
/// negotiated MTU ([`ATT_MTU_MAX`]) plus a few bytes of headroom.
const REASM_CAP: usize = ATT_MTU_MAX + 8;

/// Reassembles L2CAP frames that arrive spread across several LL data PDUs.
///
/// An LL data PDU with LLID `0b10` *starts* an L2CAP frame and carries its
/// `len(2) + CID(2)` header; LLID `0b01` is a *continuation* fragment whose
/// bytes are raw payload with no header at all. An earlier revision matched
/// `0b10 | 0b01` in a single arm and parsed a header out of both, so every
/// continuation was decoded as though its first two bytes were a length and its
/// next two a CID. The frame was then dropped (as a bogus CID) or, worse,
/// handed to the ATT decoder with a payload byte in the opcode position — which
/// is the most likely explanation for the `peer ATT 0x45` seen in a capture,
/// since `0x45` is not a legal ATT opcode at all.
struct Reasm {
    buf: [u8; REASM_CAP],
    /// Payload bytes collected so far (the 4-byte L2CAP header excluded).
    have: usize,
    /// Payload length the header promised; `None` when no frame is in progress.
    need: Option<usize>,
    cid: u16,
}

impl Reasm {
    fn new() -> Self {
        Self { buf: [0u8; REASM_CAP], have: 0, need: None, cid: 0 }
    }

    fn clear(&mut self) {
        self.have = 0;
        self.need = None;
    }

    /// Feeds one LL data PDU payload. Returns `true` when a complete frame is
    /// available in [`Self::frame`] on [`Self::cid`]; the caller must then
    /// [`Self::clear`] before the next PDU.
    fn push(&mut self, llid: u8, payload: &[u8]) -> bool {
        match llid {
            0b10 => {
                // A new start discards any half-collected frame: the peer would
                // not begin a second frame before finishing the first, so a
                // leftover here means we missed the tail of the previous one.
                self.clear();
                if payload.len() < 4 {
                    return false;
                }
                let l2_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
                self.cid = u16::from_le_bytes([payload[2], payload[3]]);
                if l2_len > REASM_CAP {
                    ulogf!("  [ERR] peer L2CAP frame too large ({} B) — dropped\r\n", l2_len);
                    return false;
                }
                self.need = Some(l2_len);
                self.take(&payload[4..])
            }
            // A continuation with nothing in progress is the tail of a frame
            // whose start we missed. There is nothing to append it to.
            0b01 => self.need.is_some() && self.take(payload),
            _ => false,
        }
    }

    fn take(&mut self, bytes: &[u8]) -> bool {
        let Some(need) = self.need else {
            return false;
        };
        let n = bytes.len().min(need - self.have);
        self.buf[self.have..self.have + n].copy_from_slice(&bytes[..n]);
        self.have += n;
        self.have >= need
    }

    fn frame(&self) -> &[u8] {
        &self.buf[..self.have]
    }
}

/// Logs a Handle Value Notification / Indication and says whether it was one.
///
/// These arrive unsolicited on the same bearer as our own transactions once a
/// CCCD has been written, so both [`att_txn`] and [`listen_notifications`] have
/// to recognise them.
fn log_notification(att: &[u8]) -> bool {
    let ind = match att[0] {
        ATT_HANDLE_VALUE_NTF => false,
        ATT_HANDLE_VALUE_IND => true,
        _ => return false,
    };
    if att.len() < 3 {
        return true;
    }
    let h = u16::from_le_bytes([att[1], att[2]]);
    let value = &att[3..];
    ulogf!(
        "    {} h={:04X} len={}\r\n",
        if ind { "IND" } else { "NTF" },
        h,
        value.len()
    );
    decoder::hexdump(value, 0, 4);
    true
}

// ── ATT transaction ───────────────────────────────────────────────────────────

/// Sends one ATT request and pumps connection events until the matching ATT
/// response arrives, copying its bytes into `resp`. Returns the ATT payload
/// length, or `None` on link loss / timeout. Retransmits the request until the
/// peer acknowledges it, then sends empty PDUs while awaiting the response.
async fn att_txn(conn: &mut Conn, req: &[u8], resp: &mut [u8]) -> Option<usize> {
    let mut sent = false; // request acknowledged by the peer
    let mut miss = 0u32;
    // The one response opcode that answers `req`. Everything else arriving on
    // CID 0x0004 is the peer acting as a client on the same bearer.
    let want = req[0].wrapping_add(1);
    // An ATT PDU we owe the peer, staged ahead of our own request. See
    // [`peer_att_reply`].
    let mut owed: Option<([u8; 5], usize)> = None;
    let mut asm = Reasm::new();

    for _ in 0..MAX_EVENTS_PER_TXN {
        let tx_len = match (&owed, sent) {
            // Clear the debt first: the peer will not answer us while its own
            // request is outstanding, so our reply unblocks both directions.
            (Some((b, n)), _) => stage_att(conn, &b[..*n]),
            (None, false) => stage_att(conn, req),
            (None, true) => stage_empty(conn),
        };
        let rx = conn_event(conn, tx_len).await;
        let Some(rx) = rx else {
            miss += 1;
            // A peer that has never spoken gets a short leash; once it has
            // replied even once the link is real and we wait the full budget.
            let cap = if conn.saw_reply { MAX_CONSEC_MISS } else { MAX_CONSEC_MISS_UNPROVEN };
            if miss >= cap {
                return None;
            }
            continue;
        };
        miss = 0;
        let (new_data, acked) = update_flow(conn, &rx);
        if acked {
            // An ack retires whatever we actually put on air this event, which
            // is `owed` when there was one — not our request.
            if owed.is_some() {
                owed = None;
            } else {
                sent = true;
            }
        }
        if !new_data || rx.len == 0 {
            continue;
        }

        let buf = unsafe { &*RX_BUF.0.get() };
        let payload = &buf[2..2 + rx.len as usize];
        match rx.llid {
            0b11 => handle_ll_control(payload), // LL control PDU — ack & note
            0b10 | 0b01 => {
                // L2CAP: len(2) + CID(2) + ATT, possibly split across PDUs.
                if !asm.push(rx.llid, payload) {
                    continue;
                }
                let cid = asm.cid;
                let frame = asm.frame();
                if cid != 0x0004 {
                    // SMP and LE signalling share the bearer. Not fatal, but a
                    // peer that opens with a pairing request is a peer whose
                    // attributes we may simply not be allowed to read.
                    ulogf!("  peer L2CAP cid=0x{:04X} len={} (ignored)\r\n", cid, frame.len());
                } else if !frame.is_empty() {
                    let att = frame;
                    // Only the matching response opcode, or an error response
                    // naming our request, answers this transaction. Accepting
                    // any ATT PDU was a real bug: a peer that opens with its
                    // own `Read By Type Req` (Database Hash, Service Changed —
                    // Apple and Android both do it) had that request handed
                    // back as our service-discovery response, whereupon
                    // `discover_services` saw opcode 0x08 instead of 0x11 and
                    // bailed with `services=0` after two connection events.
                    if att[0] == want
                        || (att[0] == ATT_ERROR_RSP && att.len() >= 2 && att[1] == req[0])
                    {
                        let n = att.len().min(resp.len());
                        resp[..n].copy_from_slice(&att[..n]);
                        return Some(n);
                    }
                    if att[0] == 0x02 && att.len() >= 3 {
                        // Peer is acting as a client and negotiating MTU. Adopt
                        // the smaller of the two Rx MTUs and answer with ours, so
                        // the peer may send us PDUs up to the negotiated size.
                        let peer_rx = u16::from_le_bytes([att[1], att[2]]);
                        conn.att_mtu = negotiated_mtu(peer_rx);
                        ulogf!("  mtu = {} (peer req {})\r\n", conn.att_mtu, peer_rx);
                        owed = Some(exchange_mtu_rsp());
                    } else {
                        // A notification we subscribed to is not "unsolicited" in
                        // any useful sense; print it as the data it is.
                        if !log_notification(att) {
                            ulogf!(
                                "  peer ATT 0x{:02X} {} len={} (unsolicited)\r\n",
                                att[0],
                                att_opcode_name(att[0]),
                                att.len()
                            );
                            // Field-decode it through the same ATT decoder the main
                            // conn path uses, so a peer's service discovery (Read By
                            // Type, Find By Type Value for ANCS/Garmin/…) shows its
                            // handles + named type/value UUIDs, not a bare hexdump.
                            decoder::protocol::l2cap::att::Att.decode(att);
                        }
                        if let Some(r) = peer_att_reply(att[0]) {
                            owed = Some(r);
                        }
                    }
                }
                asm.clear();
            }
            _ => {}
        }
    }
    None
}

/// Holds the connection open for `events` connection events, sending empty PDUs
/// and printing any notification or indication the peer pushes.
///
/// Nothing is requested here; this exists because a CCCD write only takes effect
/// for as long as the link lives, so a subscription with no listening period
/// after it produces no data at all.
async fn listen_notifications(conn: &mut Conn, events: u32) {
    let mut asm = Reasm::new();
    let mut owed: Option<([u8; 5], usize)> = None;
    let mut miss = 0u32;

    for _ in 0..events {
        let tx_len = match &owed {
            Some((b, n)) => stage_att(conn, &b[..*n]),
            None => stage_empty(conn),
        };
        let Some(rx) = conn_event(conn, tx_len).await else {
            miss += 1;
            if miss >= MAX_CONSEC_MISS {
                return;
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
                let cid = asm.cid;
                let frame = asm.frame();
                if cid == 0x0004 && !frame.is_empty() {
                    if !log_notification(frame) {
                        ulogf!(
                            "  peer ATT 0x{:02X} {} len={}\r\n",
                            frame[0],
                            att_opcode_name(frame[0]),
                            frame.len()
                        );
                        decoder::protocol::l2cap::att::Att.decode(frame);
                    }
                    // An indication is retransmitted until confirmed, so the
                    // confirmation owed here is what keeps the stream moving.
                    if let Some(r) = peer_att_reply(frame[0]) {
                        owed = Some(r);
                    }
                }
                asm.clear();
            }
            _ => {}
        }
    }
}

/// Print the per-event trace collected during the connection, one line per
/// event, now that no timing depends on us.
///
/// Direction arrows match the connection follower's convention: `C->P` is what
/// this central transmitted, `P->C` the peripheral's T_IFS reply.
async fn dump_trace(conn: &Conn) {
    let n = (conn.ev_total as usize).min(TRACE_EVENTS);
    if n == 0 {
        return;
    }
    ulog!("  ev ch | C->P llid sn nesn len | P->C  a c e llid sn nesn len gap\r\n");
    for (i, t) in conn.trace[..n].iter().enumerate() {
        ulogf!(
            "  {:2} {:2} | C->P    {} {}    {} {:3} | P->C  {} {} {}    {} {}    {} {:3} {}us\r\n",
            i + 1,
            t.ch,
            t.tx_hdr & 0x03,
            (t.tx_hdr >> 3) & 1,
            (t.tx_hdr >> 2) & 1,
            t.tx_len,
            t.flags & 1,          // EVENTS_ADDRESS — reply preamble+AA matched
            (t.flags >> 1) & 1,   // EVENTS_CRCOK
            (t.flags >> 2) & 1,   // reply END seen
            t.rx_hdr & 0x03,
            (t.rx_hdr >> 3) & 1,
            (t.rx_hdr >> 2) & 1,
            t.rx_len,
            t.gap_us
        );
        // The LOG channel is 32 deep and `ulogf!` drops on full. A 24-line burst
        // with no yield races the USB drain task and would silently lose the tail
        // — exactly the events that show what the peer stopped answering.
        if i % 8 == 7 {
            Timer::after(Duration::from_millis(4)).await;
        }
    }
}

/// Minimal LL control handling: we do not negotiate features/version/MTU, but we
/// note a peer-initiated termination so the caller can stop cleanly.
fn handle_ll_control(payload: &[u8]) {
    if let Some(&opcode) = payload.first()
        && opcode == 0x02
    {
        // LL_TERMINATE_IND. A peer ending the link is a normal event, not our
        // error, so it carries no [ERR] tag; the decoded reason name still says
        // whether it was a clean close (remote-user-terminated) or a failure
        // (conn-timeout, terminated-mic-failure) for anyone reading.
        let reason = payload.get(1).copied().unwrap_or(0);
        let name = crate::decoder::protocol::ll::error_name(reason);
        ulogf!("peer LL_TERMINATE_IND reason=0x{:02X} ({})\r\n", reason, name);
    }
}

// ── GATT decode (this module owns it) ─────────────────────────────────────────

/// If `uuid_le` (little-endian, on-air order) is a 16-bit UUID widened to the
/// Bluetooth base UUID `0000xxxx-0000-1000-8000-00805F9B34FB`, return the 16-bit
/// value. `None` for a genuinely 128-bit (vendor) UUID.
fn base_uuid_16(uuid_le: &[u8]) -> Option<u16> {
    // The base UUID in on-air (little-endian) order, with the two 16-bit-value
    // bytes at [12..14] left out and the top two bytes at [14..16] zero.
    const BASE_LE: [u8; 12] =
        [0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00];
    if uuid_le.len() == 16 && uuid_le[..12] == BASE_LE && uuid_le[14] == 0 && uuid_le[15] == 0 {
        Some(u16::from_le_bytes([uuid_le[12], uuid_le[13]]))
    } else {
        None
    }
}

/// Name for a well-known 16-bit GATT UUID: declarations, descriptors, services
/// and characteristics.
///
/// This used to be a hand-picked shortlist of ~35 UUIDs, so a discovery on any
/// device outside it printed bare numbers. The shared `decoder::uuid_name`
/// table is built from the SIG's own `uuids/*.yaml` and now carries the
/// declaration, descriptor and characteristic lists alongside the service ones
/// — about 1,100 names, refreshed by `scripts/refresh_data.py`. It is read from
/// the external-flash asset image, so names need a provisioned device.
fn gatt_uuid16_name(u: u16) -> Option<&'static str> {
    // U-tec / ULTRALOQ vendor GATT UUIDs (0x72xx range, sent as the Bluetooth
    // base-UUID short form). These are not SIG-assigned, so they are named here
    // before the SIG table. Which key characteristic a lock exposes even reveals
    // its auth handshake (static vs MD5 vs ECC). UUIDs from the utecio library:
    // https://github.com/inventor7777/ultraloq-ble-ha
    let vendor = match u {
        0x7200 => Some("U-tec Lock"),
        0x7201 => Some("U-tec Data"),
        0x7220 => Some("U-tec Key (static)"),
        0x7221 => Some("U-tec Key (ECC)"),
        0x7223 => Some("U-tec Key (MD5)"),
        _ => None,
    };
    vendor.or_else(|| crate::decoder::uuid_name(u))
}

/// Decodes the characteristic-properties bitfield (from a 0x2803 declaration).
fn char_props(props: u8, out: &mut heapless::String<48>) {
    use core::fmt::Write;
    let flags = [
        (0x01, "bcast"),
        (0x02, "read"),
        (0x04, "wr-nr"),
        (0x08, "write"),
        (0x10, "notify"),
        (0x20, "indicate"),
        (0x40, "auth-sw"),
        (0x80, "ext"),
    ];
    let mut first = true;
    for (bit, name) in flags {
        if props & bit != 0 {
            if !first {
                let _ = out.push(',');
            }
            let _ = write!(out, "{}", name);
            first = false;
        }
    }
}

/// ATT error-code name (subset). Shared with the passive follower
/// ([`crate::conn_follow`]), which decodes ATT it captures off the air.
pub fn att_error_name(code: u8) -> &'static str {
    // Core Vol 3 Part F Table 3.4 + the Common Profile/Service error codes; the
    // 0x80–0x9F range is per-profile "application error". (Value list cross-checked
    // against Wireshark's error_code_vals; no code copied.)
    match code {
        0x01 => "invalid-handle",
        0x02 => "read-not-permitted",
        0x03 => "write-not-permitted",
        0x04 => "invalid-pdu",
        0x05 => "insufficient-authentication",
        0x06 => "request-not-supported",
        0x07 => "invalid-offset",
        0x08 => "insufficient-authorization",
        0x09 => "prepare-queue-full",
        0x0A => "attribute-not-found",
        0x0B => "attribute-not-long",
        0x0C => "insufficient-encryption-key-size",
        0x0D => "invalid-attribute-value-length",
        0x0E => "unlikely-error",
        0x0F => "insufficient-encryption",
        0x10 => "unsupported-group-type",
        0x11 => "insufficient-resources",
        0x12 => "database-out-of-sync",
        0x13 => "value-not-allowed",
        0x80..=0x9F => "application-error",
        0xFC => "write-request-rejected",
        0xFD => "cccd-improperly-configured",
        0xFE => "procedure-already-in-progress",
        0xFF => "out-of-range",
        _ => "?",
    }
}

// ── ATT opcodes ───────────────────────────────────────────────────────────────
const ATT_ERROR_RSP: u8 = 0x01;
const ATT_READ_BY_TYPE_REQ: u8 = 0x08;
const ATT_READ_BY_TYPE_RSP: u8 = 0x09;
const ATT_READ_REQ: u8 = 0x0A;
const ATT_READ_RSP: u8 = 0x0B;
const ATT_READ_BY_GROUP_REQ: u8 = 0x10;
const ATT_READ_BY_GROUP_RSP: u8 = 0x11;
const ATT_FIND_INFO_REQ: u8 = 0x04;
const ATT_FIND_INFO_RSP: u8 = 0x05;
const ATT_READ_BLOB_REQ: u8 = 0x0C;
const ATT_READ_BLOB_RSP: u8 = 0x0D;
const ATT_WRITE_REQ: u8 = 0x12;
const ATT_WRITE_RSP: u8 = 0x13;
const ATT_HANDLE_VALUE_NTF: u8 = 0x1B;
const ATT_HANDLE_VALUE_IND: u8 = 0x1D;

/// The Client Characteristic Configuration descriptor (CCCD). Writing `01 00`
/// here enables notifications, `02 00` indications.
const UUID_CCCD: u16 = 0x2902;

/// "Attribute Not Long" — the peer's way of saying a Read Blob is pointless
/// because the whole value already fitted in the Read Response.
const ATT_ERR_NOT_LONG: u8 = 0x0B;
/// "Invalid Offset" — we asked past the end of the value.
const ATT_ERR_INVALID_OFFSET: u8 = 0x07;

/// Name for an ATT opcode, for the unsolicited-PDU log line.
fn att_opcode_name(op: u8) -> &'static str {
    match op {
        0x01 => "Error Rsp",
        0x02 => "Exchange MTU Req",
        0x03 => "Exchange MTU Rsp",
        0x04 => "Find Information Req",
        0x05 => "Find Information Rsp",
        0x06 => "Find By Type Value Req",
        0x07 => "Find By Type Value Rsp",
        0x08 => "Read By Type Req",
        0x09 => "Read By Type Rsp",
        0x0A => "Read Req",
        0x0B => "Read Rsp",
        0x0C => "Read Blob Req",
        0x0D => "Read Blob Rsp",
        0x0E => "Read Multiple Req",
        0x0F => "Read Multiple Rsp",
        0x10 => "Read By Group Type Req",
        0x11 => "Read By Group Type Rsp",
        0x12 => "Write Req",
        0x13 => "Write Rsp",
        0x16 => "Prepare Write Req",
        0x17 => "Prepare Write Rsp",
        0x18 => "Execute Write Req",
        0x19 => "Execute Write Rsp",
        0x1B => "Handle Value Notification",
        0x1D => "Handle Value Indication",
        0x1E => "Handle Value Confirmation",
        0x52 => "Write Command",
        _ => "?",
    }
}

/// What we owe the peer for an ATT PDU that is not the response we asked for.
///
/// ATT is stop-and-wait *per direction*: a peer with a request outstanding will
/// not answer ours until it gets a reply, so dropping its request silently
/// deadlocks the bearer until [`MAX_EVENTS_PER_TXN`] runs out. We are a pure
/// client with no attribute database, so most requests get Request Not
/// Supported (0x06) — a legal answer, and unlike silence it lets the peer move
/// on to serving us. Exchange MTU is the exception: it gets a real response.
///
/// Returns the PDU bytes and their length, or `None` when nothing is owed.
fn peer_att_reply(op: u8) -> Option<([u8; 5], usize)> {
    match op {
        // Exchange MTU Req: answer with our Rx MTU. The `att_txn` loop also
        // adopts the peer's value into `conn.att_mtu`; this covers other callers.
        0x02 => {
            let (b, n) = exchange_mtu_rsp();
            Some((b, n))
        }
        // An indication is retransmitted until confirmed, so this one matters
        // as much as the error responses.
        0x1D => Some(([0x1E, 0, 0, 0, 0], 1)),
        // Notifications and commands (bit 6) are fire-and-forget by definition.
        0x1B => None,
        _ if op & 0x40 != 0 => None,
        // Requests are the even opcodes in 0x02..=0x18; the odd ones are
        // responses and already failed to match the transaction above.
        0x02..=0x18 if op.is_multiple_of(2) => Some(([ATT_ERROR_RSP, op, 0x00, 0x00, 0x06], 5)),
        _ => None,
    }
}

/// Clamps a peer's advertised Rx MTU to the range we support: at least
/// [`ATT_MTU_DEFAULT`], at most [`ATT_MTU_MAX`].
fn negotiated_mtu(peer_rx: u16) -> u16 {
    peer_rx.clamp(ATT_MTU_DEFAULT as u16, ATT_MTU_MAX as u16)
}

/// Our Exchange MTU Response, advertising [`ATT_MTU_MAX`] as our server Rx MTU.
fn exchange_mtu_rsp() -> ([u8; 5], usize) {
    let m = ATT_MTU_MAX as u16;
    ([0x03, (m & 0xFF) as u8, (m >> 8) as u8, 0, 0], 3)
}

/// Negotiates a larger ATT MTU as the first transaction on the bearer, so a full
/// characteristic value fits in one Read Response. Best-effort: on a peer that
/// declines, errors, or never answers, the link keeps [`ATT_MTU_DEFAULT`].
async fn exchange_mtu(conn: &mut Conn) {
    let m = ATT_MTU_MAX as u16;
    let req = [0x02, (m & 0xFF) as u8, (m >> 8) as u8];
    let mut resp = [0u8; ATT_MTU_MAX];
    // One uniform line whatever the outcome: `mtu = <settled value> (<result>)`.
    // The settled value is what every read below will use, so it leads; the
    // parenthetical says how we got there. Silence still costs up to
    // MAX_EVENTS_PER_TXN events before the bearer moves on, so it earns a line —
    // an enumeration running at ATT_MTU_DEFAULT looks identical to one that never
    // asked.
    let Some(n) = att_txn(conn, &req, &mut resp).await else {
        ulogf!("  mtu = {} (unanswered)\r\n", conn.att_mtu);
        return;
    };
    if n >= 3 && resp[0] == 0x03 {
        let peer_rx = u16::from_le_bytes([resp[1], resp[2]]);
        conn.att_mtu = negotiated_mtu(peer_rx);
        ulogf!("  mtu = {} (req {}, peer {})\r\n", conn.att_mtu, m, peer_rx);
    } else if n >= 5 && resp[0] == 0x01 {
        // Error Response: [opcode 0x01][req opcode][handle lo][handle hi][code].
        ulogf!("  mtu = {} (peer rejected err=0x{:02X})\r\n", conn.att_mtu, resp[4]);
    } else {
        ulogf!("  mtu = {} (bad reply op=0x{:02X} len={})\r\n", conn.att_mtu, resp[0], n);
    }
}

#[derive(Clone, Copy)]
struct Service {
    start: u16,
    end: u16,
    /// The service UUID as it appeared on air (little-endian, 2 or 16 bytes),
    /// kept so the service header can be printed grouped with its characteristics
    /// rather than at discovery time.
    uuid: [u8; 16],
    uuid_len: u8,
}

#[derive(Clone, Copy)]
struct Characteristic {
    decl_handle: u16,
    value_handle: u16,
    props: u8,
    /// The characteristic's 16-bit SIG UUID, or `None` for a 128-bit UUID. Lets
    /// `read_value` recognize well-known values (e.g. Current Time) to decode.
    uuid16: Option<u16>,
    /// The full UUID on air (little-endian, 2 or 16 bytes), kept so the
    /// characteristic can be printed grouped with its value and descriptors.
    uuid: [u8; 16],
    uuid_len: u8,
}

/// Formats a UUID (16-bit or 128-bit) plus any known name into a log fragment.
fn write_uuid(s: &mut decoder::LogStr, uuid_le: &[u8]) {
    use core::fmt::Write;
    if uuid_le.len() == 2 {
        let u = u16::from_le_bytes([uuid_le[0], uuid_le[1]]);
        let _ = write!(s, "0x{:04X}", u);
        if let Some(n) = gatt_uuid16_name(u) {
            let _ = write!(s, " ({})", n);
        }
    } else if let Some(u) = base_uuid_16(uuid_le) {
        // A 16-bit UUID a peer widened to the full Bluetooth base UUID; show and
        // name it as the 16-bit it really is rather than 32 hex digits.
        let _ = write!(s, "0x{:04X}", u);
        if let Some(n) = gatt_uuid16_name(u) {
            let _ = write!(s, " ({})", n);
        }
    } else {
        // 128-bit UUID, big-endian display.
        let _ = s.push_str("0x");
        for b in uuid_le.iter().rev() {
            let _ = write!(s, "{:02X}", b);
        }
        // Name the well-known Apple vendor UUIDs. The on-air bytes are
        // little-endian; reverse them to the display (big-endian) order the table
        // is written in, then look up.
        if uuid_le.len() == 16 {
            let mut be = [0u8; 16];
            for (i, b) in uuid_le.iter().rev().enumerate() {
                be[i] = *b;
            }
            if let Some(n) = gatt_uuid128_name(&be) {
                let _ = write!(s, " ({})", n);
            }
        }
    }
}

/// Name for a well-known 128-bit GATT UUID, given in display (big-endian) order.
///
/// Apple's ANCS and AMS service/characteristic UUIDs are from Apple's published
/// specifications (Apple Notification Center Service / Apple Media Service). The
/// Continuity and Nearby UUIDs are from community reverse-engineering and appear
/// in this firmware's own captures of an Apple Watch. `None` for anything else,
/// which then prints as the raw 128-bit value.
fn gatt_uuid128_name(uuid_be: &[u8; 16]) -> Option<&'static str> {
    const T: &[(&str, [u8; 16])] = &[
        ("Apple ANCS", [0x79, 0x05, 0xF4, 0x31, 0xB5, 0xCE, 0x4E, 0x99,
                        0xA4, 0x0F, 0x4B, 0x1E, 0x12, 0x2D, 0x00, 0xD0]),
        ("ANCS Notification Source", [0x9F, 0xBF, 0x12, 0x0D, 0x63, 0x01, 0x42, 0xD9,
                                      0x8C, 0x58, 0x25, 0xE6, 0x99, 0xA2, 0x1D, 0xBD]),
        ("ANCS Control Point", [0x69, 0xD1, 0xD8, 0xF3, 0x45, 0xE1, 0x49, 0xA8,
                                0x98, 0x21, 0x9B, 0xBD, 0xFD, 0xAA, 0xD9, 0xD9]),
        ("ANCS Data Source", [0x22, 0xEA, 0xC6, 0xE9, 0x24, 0xD6, 0x4B, 0xB5,
                              0xBE, 0x44, 0xB3, 0x6A, 0xCE, 0x7C, 0x7B, 0xFB]),
        ("Apple AMS", [0x89, 0xD3, 0x50, 0x2B, 0x0F, 0x36, 0x43, 0x3A,
                       0x8E, 0xF4, 0xC5, 0x02, 0xAD, 0x55, 0xF8, 0xDC]),
        ("AMS Remote Command", [0x9B, 0x3C, 0x81, 0xD8, 0x57, 0xB1, 0x4A, 0x8A,
                                0xB8, 0xDF, 0x0E, 0x56, 0xF7, 0xCA, 0x51, 0xC2]),
        ("AMS Entity Update", [0x2F, 0x7C, 0xAB, 0xCE, 0x80, 0x8D, 0x41, 0x1F,
                               0x9A, 0x0C, 0xBB, 0x92, 0xBA, 0x96, 0xC1, 0x02]),
        ("AMS Entity Attribute", [0xC6, 0xB2, 0xF3, 0x8C, 0x23, 0xAB, 0x46, 0xD8,
                                  0xA6, 0xAB, 0xA3, 0xA8, 0x70, 0xBB, 0xD5, 0xD7]),
        ("Apple Continuity", [0xD0, 0x61, 0x1E, 0x78, 0xBB, 0xB4, 0x45, 0x91,
                              0xA5, 0xF8, 0x48, 0x79, 0x10, 0xAE, 0x43, 0x66]),
        ("Apple Continuity char", [0x86, 0x67, 0x55, 0x6C, 0x9A, 0x37, 0x4C, 0x91,
                                   0x84, 0xED, 0x54, 0xEE, 0x27, 0xD9, 0x00, 0x49]),
        ("Apple Nearby", [0x9F, 0xA4, 0x80, 0xE0, 0x49, 0x67, 0x45, 0x42,
                          0x93, 0x90, 0xD3, 0x43, 0xDC, 0x5D, 0x04, 0xAE]),
        ("Apple Nearby char", [0xAF, 0x0B, 0xAD, 0xB1, 0x5B, 0x99, 0x43, 0xCD,
                               0x91, 0x7A, 0xA7, 0x7B, 0xC5, 0x49, 0xE3, 0xCC]),
    ];
    for (name, u) in T {
        if u == uuid_be {
            return Some(name);
        }
    }
    None
}

// ── GATT walk ─────────────────────────────────────────────────────────────────

/// Discovers all primary services (Read By Group Type, UUID 0x2800), collecting
/// them into `services`. Each service is printed later by [`enumerate`], grouped
/// above the characteristics it contains.
async fn discover_services(conn: &mut Conn, services: &mut Vec<Service, MAX_SERVICES>) {
    let mut start: u16 = 0x0001;
    loop {
        let req = [
            ATT_READ_BY_GROUP_REQ,
            (start & 0xFF) as u8,
            (start >> 8) as u8,
            0xFF,
            0xFF,
            0x00,
            0x28, // 0x2800 Primary Service
        ];
        let mut resp = [0u8; ATT_MTU_MAX];
        let Some(n) = att_txn(conn, &req, &mut resp).await else {
            ulog!("  [ERR] (service discovery: link lost)\r\n");
            return;
        };
        if n == 0 {
            return;
        }
        if resp[0] == ATT_ERROR_RSP {
            // 0x0A attribute-not-found terminates the walk normally.
            return;
        }
        if resp[0] != ATT_READ_BY_GROUP_RSP || n < 2 {
            // Bailing here used to be silent, so a peer whose reply we mishandled
            // was indistinguishable in the log from a peer with no services.
            ulogf!(
                "  [ERR] (service discovery: unexpected ATT 0x{:02X} {} len={})\r\n",
                resp[0], att_opcode_name(resp[0]), n
            );
            return;
        }
        let each = resp[1] as usize; // length of each (handle,end,uuid) tuple
        if each < 6 {
            ulogf!("  [ERR] (service discovery: bad tuple length {})\r\n", each);
            return;
        }
        let mut last_end = start;
        for tuple in resp[2..n].chunks_exact(each) {
            let h = u16::from_le_bytes([tuple[0], tuple[1]]);
            let e = u16::from_le_bytes([tuple[2], tuple[3]]);
            let uuid = &tuple[4..each];

            let mut ub = [0u8; 16];
            let ul = uuid.len().min(16);
            ub[..ul].copy_from_slice(&uuid[..ul]);
            let _ = services.push(Service { start: h, end: e, uuid: ub, uuid_len: ul as u8 });
            last_end = e;
        }
        if last_end == 0xFFFF || last_end < start {
            return;
        }
        start = last_end + 1;
    }
}

/// Discovers the characteristics of one service (Read By Type, UUID 0x2803),
/// collecting them for the caller to print, read and subscribe. Each is printed
/// later by [`enumerate`], grouped under its service.
async fn discover_characteristics(
    conn: &mut Conn,
    svc: &Service,
    chars: &mut Vec<Characteristic, MAX_CHARS_PER_SVC>,
) {
    let mut start = svc.start;
    while start <= svc.end {
        let req = [
            ATT_READ_BY_TYPE_REQ,
            (start & 0xFF) as u8,
            (start >> 8) as u8,
            (svc.end & 0xFF) as u8,
            (svc.end >> 8) as u8,
            0x03,
            0x28, // 0x2803 Characteristic
        ];
        let mut resp = [0u8; ATT_MTU_MAX];
        let Some(n) = att_txn(conn, &req, &mut resp).await else {
            return;
        };
        if n == 0 || resp[0] == ATT_ERROR_RSP || resp[0] != ATT_READ_BY_TYPE_RSP || n < 2 {
            return;
        }
        let each = resp[1] as usize; // handle(2) + value = 2 + (1 props + 2 vhandle + uuid)
        if each < 7 {
            return;
        }
        let mut last = start;
        for tuple in resp[2..n].chunks_exact(each) {
            let decl = u16::from_le_bytes([tuple[0], tuple[1]]);
            let props = tuple[2];
            let vhandle = u16::from_le_bytes([tuple[3], tuple[4]]);
            let uuid = &tuple[5..each];

            let mut ub = [0u8; 16];
            let ul = uuid.len().min(16);
            ub[..ul].copy_from_slice(&uuid[..ul]);
            let _ = chars.push(Characteristic {
                decl_handle: decl,
                value_handle: vhandle,
                props,
                uuid16: (uuid.len() == 2).then(|| u16::from_le_bytes([uuid[0], uuid[1]])),
                uuid: ub,
                uuid_len: ul as u8,
            });
            last = decl;
        }
        if last == 0xFFFF || last < start {
            return;
        }
        start = last + 1;
    }
}

/// Discovers the descriptors that sit between a characteristic's value handle and
/// the next characteristic (or the service end), via Find Information.
///
/// Returns the handle of this characteristic's CCCD (`0x2902`) if it has one, so
/// the caller can subscribe. There is at most one per characteristic.
async fn discover_descriptors(conn: &mut Conn, from: u16, to: u16) -> Option<u16> {
    let mut cccd = None;
    if from > to {
        return None;
    }
    let mut start = from;
    while start <= to {
        let req = [
            ATT_FIND_INFO_REQ,
            (start & 0xFF) as u8,
            (start >> 8) as u8,
            (to & 0xFF) as u8,
            (to >> 8) as u8,
        ];
        let mut resp = [0u8; ATT_MTU_MAX];
        let Some(n) = att_txn(conn, &req, &mut resp).await else {
            return cccd;
        };
        if n == 0 || resp[0] == ATT_ERROR_RSP || resp[0] != ATT_FIND_INFO_RSP || n < 2 {
            return cccd;
        }
        let fmt = resp[1]; // 0x01 = 16-bit UUIDs, 0x02 = 128-bit
        let each = if fmt == 0x01 { 4 } else { 18 };
        let mut last = start;
        for tuple in resp[2..n].chunks_exact(each) {
            let h = u16::from_le_bytes([tuple[0], tuple[1]]);
            let uuid = &tuple[2..each];
            if each == 4 && u16::from_le_bytes([uuid[0], uuid[1]]) == UUID_CCCD {
                cccd = Some(h);
            }
            let mut s = decoder::LogStr::new();
            use core::fmt::Write;
            let _ = write!(s, "        - dsc h={:04X} ", h);
            write_uuid(&mut s, uuid);
            decoder::emit(s);
            last = h;
        }
        if last == 0xFFFF || last < start {
            return cccd;
        }
        start = last + 1;
    }
    cccd
}

/// Enables notifications (or indications) on a characteristic by writing its
/// CCCD, and reports what the peer said.
///
/// Returns true if the subscription was accepted. Most failures are
/// `insufficient-authentication` (0x05) — the same gate that blocks reads of
/// encrypted attributes, since a CCCD write is a write to the peer's database.
async fn subscribe(conn: &mut Conn, cccd: u16, props: u8) -> bool {
    // Prefer notification when the characteristic offers both: an indication
    // costs a confirmation round-trip per value and carries no extra data.
    let val: u16 = if props & 0x10 != 0 { 0x0001 } else { 0x0002 };
    let req = [
        ATT_WRITE_REQ,
        (cccd & 0xFF) as u8,
        (cccd >> 8) as u8,
        (val & 0xFF) as u8,
        (val >> 8) as u8,
    ];
    let mut resp = [0u8; ATT_MTU_MAX];
    let Some(n) = att_txn(conn, &req, &mut resp).await else {
        return false;
    };
    if n >= 1 && resp[0] == ATT_WRITE_RSP {
        ulogf!(
            "          sub h={:04X} {} ok\r\n",
            cccd,
            if val == 1 { "notify" } else { "indicate" }
        );
        return true;
    }
    if n >= 5 && resp[0] == ATT_ERROR_RSP {
        ulogf!("          sub h={:04X} err=0x{:02X} ({})\r\n", cccd, resp[4], att_error_name(resp[4]));
    }
    false
}

/// Reads a characteristic value (ATT Read Request) and prints it (hex + ASCII),
/// or the ATT error the peer returned.
/// Bluetooth "Day of Week" code (1 = Monday … 7 = Sunday, 0 = unknown) → label.
fn dow_name(d: u8) -> &'static str {
    match d {
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        6 => "Sat",
        7 => "Sun",
        _ => "?",
    }
}

/// A broken-down wall-clock decoded from a Current Time / Date Time value.
struct WallTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    min: u8,
    sec: u8,
    /// Day-of-week code (0 = unknown, 1 = Monday … 7 = Sunday); 0 if absent.
    dow: u8,
    /// Current Time adjust-reason bitfield; 0 if absent.
    adj: u8,
    /// Unix epoch seconds for the fields above.
    epoch: u32,
}

/// Decode the 7-byte Date Time prefix shared by Current Time (0x2A2B), Exact
/// Time 256 (0x2A0C) and Date Time (0x2A08), plus the day-of-week / adjust-reason
/// bytes where present — but only when the value passes a plausibility gate (so a
/// garbage read never anchors a bogus clock). `None` for any other characteristic
/// or an implausible value.
fn decode_time(uuid16: u16, v: &[u8]) -> Option<WallTime> {
    if !matches!(uuid16, 0x2A2B | 0x2A0C | 0x2A08) || v.len() < 7 {
        return None;
    }
    let year = u16::from_le_bytes([v[0], v[1]]);
    let (month, day, hour, min, sec) = (v[2], v[3], v[4], v[5], v[6]);
    if !(2000..=2100).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour >= 24
        || min >= 60
        || sec >= 60
    {
        return None;
    }
    Some(WallTime {
        year,
        month,
        day,
        hour,
        min,
        sec,
        dow: if v.len() >= 8 { v[7] } else { 0 },
        // adjust_reason is the trailing byte of Current Time only (index 9).
        adj: if uuid16 == 0x2A2B && v.len() >= 10 { v[9] } else { 0 },
        epoch: crate::wallclock::to_epoch(year, month, day, hour, min, sec),
    })
}

/// Name for a high-prevalence USB Implementer's Forum vendor id, as carried by a
/// PnP ID (0x2A50) with source 0x02. USB VIDs are a registry separate from the
/// SIG Company Identifiers, so [`decoder::company_name`] cannot name them; this
/// is a curated set of the consumer vendors that actually appear on BLE
/// peripherals (Sony, Telink and Microsoft were all seen with src=0x02 in
/// captures). `None` for anything outside the set — the raw VID still prints.
fn usb_vid_name(vid: u16) -> Option<&'static str> {
    Some(match vid {
        0x05AC => "Apple",
        0x04E8 => "Samsung",
        0x18D1 => "Google",
        0x054C => "Sony",
        0x045E => "Microsoft",
        0x05A7 => "Bose",
        0x046D => "Logitech",
        0x1915 => "Nordic Semiconductor",
        0x091E => "Garmin",
        0x057E => "Nintendo",
        0x2717 => "Xiaomi",
        0x248A => "Telink Semiconductor",
        0x0A12 => "Cambridge Silicon Radio",
        0x0BDA => "Realtek",
        0x8087 => "Intel",
        0x22B8 => "Motorola",
        0x0BB4 => "HTC",
        0x1949 => "Amazon",
        _ => return None,
    })
}

/// Decode a small set of well-known SIG characteristic values into a readable
/// one-line form, returning the decoded line and the number of leading bytes it
/// consumed — so the caller hex-dumps only whatever trails the decoded fields.
/// `None` for anything not specifically handled (the caller then dumps the whole
/// value). Time characteristics are handled separately by [`decode_time`], which
/// also anchors the wall-clock.
fn decode_known_value(uuid16: u16, v: &[u8]) -> Option<(decoder::LogStr, usize)> {
    use core::fmt::Write;
    let mut s = decoder::LogStr::new();
    let consumed = match uuid16 {
        // Device Name + Device Information Service strings: UTF-8, NUL-trimmed.
        // The whole value is the string (trailing NULs are padding, not data),
        // so nothing is left to dump.
        0x2A00 | 0x2A24 | 0x2A25 | 0x2A26 | 0x2A27 | 0x2A28 | 0x2A29 => {
            let end = v.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
            let text = core::str::from_utf8(&v[..end]).ok()?;
            let _ = write!(s, "        = \"{}\"", text);
            v.len()
        }
        // Battery Level: one byte, percent.
        0x2A19 if !v.is_empty() => {
            let _ = write!(s, "        = {}%", v[0]);
            1
        }
        // Appearance: 16-bit GAP category.
        0x2A01 if v.len() >= 2 => {
            let a = u16::from_le_bytes([v[0], v[1]]);
            let _ = write!(s, "        = appearance 0x{:04X} ({})", a, decoder::appearance_name(a));
            2
        }
        // Peripheral Preferred Connection Parameters: 4× u16 (interval unit
        // 1.25 ms, timeout unit 10 ms).
        0x2A04 if v.len() >= 8 => {
            let mn = u16::from_le_bytes([v[0], v[1]]) as u32 * 5 / 4;
            let mx = u16::from_le_bytes([v[2], v[3]]) as u32 * 5 / 4;
            let lat = u16::from_le_bytes([v[4], v[5]]);
            let to = u16::from_le_bytes([v[6], v[7]]) as u32 * 10;
            let _ = write!(s, "        = conn {}-{}ms latency={} timeout={}ms", mn, mx, lat, to);
            8
        }
        // PnP ID: source(1) + vendor(2) + product(2) + version(2). Source 0x01
        // means the vendor id is a SIG Company Identifier.
        0x2A50 if v.len() >= 7 => {
            let src = v[0];
            let vid = u16::from_le_bytes([v[1], v[2]]);
            let pid = u16::from_le_bytes([v[3], v[4]]);
            let ver = u16::from_le_bytes([v[5], v[6]]);
            let _ = write!(s, "        = pnp src={} vid=0x{:04X}", src, vid);
            // src 0x01 = Bluetooth SIG Company ID; src 0x02 = USB-IF Vendor ID.
            // The USB form is common in the wild (Sony/Telink/MS seen in captures)
            // and needs its own table — the SIG company DB doesn't cover USB VIDs.
            let vendor = match src {
                0x01 => decoder::company_name(vid),
                0x02 => usb_vid_name(vid),
                _ => None,
            };
            if let Some(name) = vendor {
                let _ = write!(s, " ({})", name);
            }
            let _ = write!(s, " pid=0x{:04X} ver=0x{:04X}", pid, ver);
            7
        }
        // System ID: 40-bit manufacturer id (v[0..5]) + 24-bit OUI (v[5..8]),
        // each least-significant octet first.
        0x2A23 if v.len() >= 8 => {
            let oui = (v[7] as u32) << 16 | (v[6] as u32) << 8 | v[5] as u32;
            let _ = write!(s, "        = systemid oui={:06X}", oui);
            if let Some(name) = decoder::oui_vendor(oui, None) {
                let _ = write!(s, " ({})", name);
            }
            8
        }
        // Database Hash: 128-bit AES-CMAC over the peer's attribute table (GATT
        // caching, BLE 5.1+). Opaque, but a stable fingerprint of the GATT layout
        // — render it as one hash line instead of a hexdump.
        0x2B2A if v.len() == 16 => {
            let _ = s.push_str("        = db-hash ");
            for b in v {
                let _ = write!(s, "{:02X}", b);
            }
            16
        }
        _ => return None,
    };
    Some((s, consumed))
}

async fn read_value(conn: &mut Conn, ch: &Characteristic) {
    let h = ch.value_handle;
    let req = [ATT_READ_REQ, (h & 0xFF) as u8, (h >> 8) as u8];
    let mut resp = [0u8; ATT_MTU_MAX];
    let Some(n) = att_txn(conn, &req, &mut resp).await else {
        return;
    };
    if n == 0 {
        return;
    }
    if resp[0] == ATT_ERROR_RSP && n >= 5 {
        ulogf!("        [ERR] read h={:04X} err=0x{:02X} ({})\r\n", h, resp[4], att_error_name(resp[4]));
        return;
    }
    if resp[0] != ATT_READ_RSP {
        return;
    }

    let mut value = [0u8; ATT_VALUE_CAP];
    let mut len = (n - 1).min(ATT_VALUE_CAP);
    value[..len].copy_from_slice(&resp[1..1 + len]);

    // A Read Response that exactly fills the MTU is the only signal that a value
    // is longer than the response — there is no "more follows" flag. Keep asking
    // with Read Blob until a short (or empty, or refused) reply arrives.
    let mut truncated = false;
    let mut offset_blind = false;
    let mtu = conn.att_mtu as usize;
    let mut more = len == mtu - 1;
    while more && len < ATT_VALUE_CAP {
        let off = len as u16;
        let req = [ATT_READ_BLOB_REQ, (h & 0xFF) as u8, (h >> 8) as u8,
                   (off & 0xFF) as u8, (off >> 8) as u8];
        let mut blob = [0u8; ATT_MTU_MAX];
        let Some(bn) = att_txn(conn, &req, &mut blob).await else {
            truncated = true;
            break;
        };
        if bn >= 5 && blob[0] == ATT_ERROR_RSP {
            // Not-Long and Invalid-Offset both mean "you already have it all";
            // anything else (typically 0x05) means the peer stopped short.
            if blob[4] != ATT_ERR_NOT_LONG && blob[4] != ATT_ERR_INVALID_OFFSET {
                ulogf!("        [ERR] blob h={:04X} err=0x{:02X} ({})\r\n",
                       h, blob[4], att_error_name(blob[4]));
                truncated = true;
            }
            break;
        }
        if bn < 1 || blob[0] != ATT_READ_BLOB_RSP {
            truncated = true;
            break;
        }
        let take = (bn - 1).min(ATT_VALUE_CAP - len);
        if take == 0 {
            break;
        }
        // Some embedded GATT servers ignore the Read Blob offset and re-send the
        // value from byte 0 on every request (seen on Sonova/Sennheiser audio
        // devices). Left unchecked that fills the buffer with "HeadHeadHead…"
        // garbage and burns a connection event per useless round-trip. If the
        // chunk just repeats what we already hold at the front, the peer is
        // offset-blind: keep only the bytes we can trust (the first Read
        // Response) and stop. The full value is unreachable this way — see the
        // note on MTU exchange in the log below.
        if blob[1..1 + take] == value[..take] {
            offset_blind = true;
            break;
        }
        value[len..len + take].copy_from_slice(&blob[1..1 + take]);
        len += take;
        // A short response is the end of the value; a full one means keep going.
        more = bn - 1 == mtu - 1;
    }
    if more && len == ATT_VALUE_CAP {
        truncated = true; // hit our own buffer, not the peer's end
    }

    let value = &value[..len];

    // Interpret known SIG characteristics, then dump only the bytes the decoder
    // did not account for — a fully decoded value dumps nothing, an unknown one
    // dumps from offset 0, and a partly decoded one dumps its trailing bytes at
    // their true offset. A Current Time value that decodes to a plausible date
    // also anchors the device wall-clock, so every subsequent log line's prefix
    // switches from uptime to UTC.
    let mut consumed = 0usize;
    if let Some(u) = ch.uuid16 {
        if let Some(t) = decode_time(u, value) {
            crate::wallclock::anchor(t.epoch, Instant::now());
            let mut ln = decoder::LogStr::new();
            use core::fmt::Write;
            let _ = write!(
                ln,
                "        walltime: {:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z src=0x{:04X} dow={} adj=0x{:02X}",
                t.year, t.month, t.day, t.hour, t.min, t.sec, u, dow_name(t.dow), t.adj
            );
            decoder::emit(ln);
            consumed = value.len();
        } else if let Some((ln, used)) = decode_known_value(u, value) {
            decoder::emit(ln);
            consumed = used.min(value.len());
        }
    }
    if consumed < value.len() {
        decoder::hexdump(&value[consumed..], consumed, 8);
    }

    // Length and any shortfall are only worth a line when there is something to
    // say: a value that read cleanly needs neither, since the decode or dump
    // above already carries it.
    if offset_blind {
        ulogf!("        [!] len={} peer ignores blob offset; needs larger MTU\r\n", len);
    } else if truncated {
        ulogf!("        [!] len={} truncated\r\n", len);
    }
}

/// Walks the full attribute database of the connected peer. Returns the number
/// of services found, which the caller uses to decide whether the attempt taught
/// us anything worth a long cooldown.
async fn enumerate(conn: &mut Conn) -> usize {
    // Raise the MTU first so a full characteristic value fits in one Read
    // Response; every read below then benefits from the negotiated size.
    exchange_mtu(conn).await;
    let mut services: Vec<Service, MAX_SERVICES> = Vec::new();
    discover_services(conn, &mut services).await;
    // The service count is stated once, here; the closing "enumeration complete"
    // line no longer repeats it.
    ulogf!("  services = {}\r\n", services.len());

    let mut subscribed = 0u32;
    for si in 0..services.len() {
        let svc = services[si];
        // Service header (list item), printed grouped above its characteristics.
        {
            let mut s = decoder::LogStr::new();
            use core::fmt::Write;
            let _ = write!(s, "  - svc [{:04X}-{:04X}] ", svc.start, svc.end);
            write_uuid(&mut s, &svc.uuid[..svc.uuid_len as usize]);
            decoder::emit(s);
        }

        let mut chars: Vec<Characteristic, MAX_CHARS_PER_SVC> = Vec::new();
        discover_characteristics(conn, &svc, &mut chars).await;

        for ci in 0..chars.len() {
            let ch = chars[ci];
            // Characteristic (list item under the service), then its value and
            // descriptors nested beneath it.
            {
                let mut s = decoder::LogStr::new();
                use core::fmt::Write;
                let mut pf: heapless::String<48> = heapless::String::new();
                char_props(ch.props, &mut pf);
                let _ = write!(s, "    - chr h={:04X} val={:04X} [{}] ",
                    ch.decl_handle, ch.value_handle, pf);
                write_uuid(&mut s, &ch.uuid[..ch.uuid_len as usize]);
                decoder::emit(s);
            }

            // Read readable characteristic values (properties bit 0x02) first, so
            // the value sits directly under its characteristic.
            if ch.props & 0x02 != 0 {
                read_value(conn, &ch).await;
            }

            // Descriptor range: value_handle+1 .. (next char decl - 1) or svc end.
            let desc_to = if ci + 1 < chars.len() {
                chars[ci + 1].decl_handle.saturating_sub(1)
            } else {
                svc.end
            };
            let cccd = discover_descriptors(conn, ch.value_handle + 1, desc_to).await;

            // Notify (0x10) / indicate (0x20) are only claims until the CCCD is
            // written — a characteristic can declare notify and still have no
            // CCCD, in which case there is no way to turn it on.
            if SUBSCRIBE
                && ch.props & 0x30 != 0
                && let Some(cccd) = cccd
                && subscribe(conn, cccd, ch.props).await
            {
                subscribed += 1;
            }
        }
    }

    if subscribed > 0 {
        ulogf!("  listening on {} subscription(s)\r\n", subscribed);
        listen_notifications(conn, LISTEN_EVENTS).await;
    }
    services.len()
}

// ── Teardown ──────────────────────────────────────────────────────────────────

/// Sends LL_TERMINATE_IND (best effort) and returns the radio to advertising RX.
async fn terminate(conn: &mut Conn) {
    let buf = unsafe { &mut *TX_BUF.0.get() };
    buf[0] = 0b11 | (conn.nesn << 2) | (conn.sn << 3); // LL control
    buf[1] = 2;
    buf[2] = 0x02; // LL_TERMINATE_IND
    buf[3] = 0x13; // reason: remote user terminated
    let _ = conn_event(conn, 4).await;
    radio_ensure_disabled();
    radio_configure_ble();
}

// ── Public entry ──────────────────────────────────────────────────────────────

/// One survey → connect → enumerate → disconnect cycle. Called in a loop by the
/// `gatt_task`.
pub async fn run(rng: &mut Rng) {
    led::solid(led::OFF);
    let (best, connectable) = survey(rng).await;

    // Green flash = a connectable peer is in range. Signalled whether or not we
    // are going to connect to it: the recent-enumeration filter silently drops
    // everything already walked in the last hour, and without this the board
    // sitting dark in a room full of phones looks identical to a board whose
    // receiver is broken.
    if connectable > 0 {
        // Any later signal pre-empts the pattern, so the flashes only actually
        // appear if nothing else is signalled while they run — hence the wait.
        Timer::after_millis(led::blink(led::GREEN, 2, 30, 30)).await;
    }

    let Some(cand) = best else {
        // Nothing eligible right now — idle briefly and rescan.
        led::solid(led::OFF);
        Timer::after_millis(500).await;
        return;
    };

    ulogf!(
        "target {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} rssi={} {}\r\n",
        cand.addr[5], cand.addr[4], cand.addr[3], cand.addr[2], cand.addr[1], cand.addr[0],
        cand.rssi,
        if cand.addr_random { "rand" } else { "pub" }
    );

    // Fresh access address and initiator address for this link, before anything
    // reads either back.
    CONN_AA.store(pick_access_address(rng), core::sync::atomic::Ordering::Relaxed);
    pick_conn_params(rng);
    randomize_our_addr(rng);

    let mut st = ConnectStats::default();
    let Some(mut conn) = try_connect(&cand, &mut st).await else {
        ulogf!(
            "[ERR] connect failed (pkts={} crcok={} target={} connectable={} txfail={})\r\n",
            st.pkts, st.crcok, st.target, st.connectable, st.txfail
        );
        // Yellow flash, not red: red now means "the peer answered this
        // connection event", and a solid red would be indistinguishable from a
        // link that is working.
        let flashes = led::blink(led::YELLOW, 3, 60, 60);
        // Short cooldown so the next survey looks past this peer. Without it,
        // `survey` picks the strongest advertiser and a strong peer that refuses
        // us is re-chosen forever.
        mark_attempted(cand.addr, Instant::now(), RETRY_COOLDOWN_S);
        radio_ensure_disabled();
        radio_configure_ble();
        Timer::after_millis(flashes).await;
        return;
    };

    if accept_probe_round() {
        // Sacrifice this attempt to answer the one question the connection
        // itself cannot: did the peer accept the CONNECT_IND at all?
        //
        // A peripheral that accepted stops advertising until its
        // connection-establishment timeout expires (6 connection intervals,
        // ~187 ms here); one that ignored the request keeps advertising at its
        // normal rate immediately. So the count has to be taken *inside* that
        // window — an observation made after it (as the whole 40-event attempt
        // is) sees both cases advertising and discriminates nothing.
        //
        // The absolute count is not the signal: a slow advertiser can be missed
        // by chance. The *pair* is. `scan_probe` counts the same target the same
        // way (3 × SCAN_PROBE_DWELL_MS) about a second later, when any accepted
        // link has long since timed out and the peer is definitely advertising
        // again. Silent-then-heard is the accept signature.
        let early = peer_readv_count(&cand, DIAG_READV_MS).await;
        let late = scan_probe(&cand, TURNAROUNDS[0]);
        ulogf!(
            "accept probe: advs_in_{}ms={} vs later advs={} ({})\r\n",
            DIAG_READV_MS,
            early,
            late.advs,
            if early > 0 {
                "still advertising => CONNECT_IND ignored/refused"
            } else if late.advs == 0 {
                "target silent both windows - inconclusive, retry"
            } else {
                "went quiet then came back => CONNECT_IND ACCEPTED; fault is our data channel"
            }
        );
        mark_attempted(cand.addr, Instant::now(), RETRY_COOLDOWN_S);
        radio_ensure_disabled();
        radio_configure_ble();
        return;
    }

    // Switch the radio off the advertising AA/CRC (used to send the CONNECT_IND)
    // onto this connection's access address + CRC init before the first event.
    // Without this the master data PDUs go out on the advertising AA (0x8E89BED6)
    // and the peer — listening on the connection AA — never decodes them, so it never replies.
    configure_conn_radio();

    let services = enumerate(&mut conn).await;
    // Where the link stood when the walk finished. txdone=0 → we never got a
    // master packet out; addr=0 with txdone>0 → the peer is not transmitting
    // back (CONNECT_IND refused, or our anchor is outside its window);
    // addr>0 with crcok=0 → we hear it but the CRC init / whitening is wrong.
    if DIAG_CONN_TRACE {
        ulogf!(
            "conn stats ev={} txdone={} addr={} crcok={} first_anchor={}us\r\n",
            conn.ev_total, conn.ev_txdone, conn.ev_addr, conn.ev_crcok, conn.first_late_us
        );
        dump_trace(&conn).await;
    } else if conn.ev_addr == 0 {
        // The one case that still needs saying with the table off: the whole
        // connection produced nothing, so the enumeration output above is empty
        // for a reason rather than because the peer has no attributes.
        //
        // Carry the same counters the trace line does. They cost nothing — they
        // are already accumulated on `conn` — and they are what separates "our
        // CONNECT_IND was refused" (txdone == ev_total, addr == 0) from "we are
        // anchored wrong" (first_anchor far from 0) without a reflash.
        ulogf!(
            "[ERR] peer never transmitted (ev={} txdone={} addr={} crcok={} first_anchor={}us)\r\n",
            conn.ev_total, conn.ev_txdone, conn.ev_addr, conn.ev_crcok, conn.first_late_us
        );
    }

    if conn.ev_addr == 0 && DIAG_TURNAROUND_SWEEP {
        // Never heard the peer once. Sending LL_TERMINATE_IND into that silence
        // tells us nothing; spend the time on the probe that does. See
        // [`scan_probe`] for why a SCAN_RSP is the discriminating observation.
        // Sweep the turnaround configurations rather than probing the current
        // one. A single probe of a single config produced the misreading that
        // sent this bug hunt sideways: one `rsp=1` out of twelve attempts looked
        // like "radio path OK" when it was really the hit rate of a broken
        // turnaround getting lucky. Four configs side by side, on the same peer
        // seconds apart, make that impossible to misread.
        let mut best = (0u32, 0u32, ""); // (rsp, advs, name)
        for t in TURNAROUNDS.iter() {
            // Let the USB logger drain and the host see the previous row before
            // the next probe blocks the executor again for up to PROBE_MAX_MS.
            Timer::after(Duration::from_millis(20)).await;
            let p = scan_probe(&cand, *t);
            ulogf!(
                "turnaround {}: rsp={}/{} rxend={} rxaddr={} txend={} txready={} state0={} ({})\r\n",
                t.name,
                p.rsp,
                p.advs,
                p.rxend,
                p.rxaddr,
                p.txend,
                p.txready,
                p.state0,
                if p.advs == 0 {
                    "target not heard - inconclusive"
                } else if p.txready == 0 {
                    "never ramped TX => SHORTS/ramp config"
                } else if p.txend == 0 {
                    "TX ramped but never completed => radio wedged mid-transmit"
                } else if p.rsp * 2 > p.advs {
                    "REPLY HEARD - majority"
                } else if p.rsp > 0 {
                    "occasional reply => marginal timing"
                } else if p.rxend > 0 {
                    "packets received, none a valid SCAN_RSP => CRC/whitening"
                } else if p.rxaddr > 0 {
                    "AA matched, packet never completed => on air, losing it mid-packet"
                } else {
                    "receiver never saw the reply => turnaround mistimed"
                }
            );
            // Compare on rate, not count: a row that got fewer attempts before
            // PROBE_MAX_MS expired must not lose to a lucky one-shot. The
            // is_empty() arm is load-bearing — with best.1 still 0 the
            // cross-multiplied comparison is 0 > 0 for every candidate, so
            // without it no row is ever selected.
            //
            // The low-sample penalty is add-one smoothing (rsp/(advs+1)), not a
            // minimum-attempts floor. A floor is a cliff: an `advs >= 4` gate
            // threw away a measured dflt/150 rsp=3/3 because the advertiser went
            // quiet after three adverts, and handed the win to fast/150 at 1/5.
            // Attempt counts here are noise — every row fell short of
            // PROBE_ATTEMPTS — so a floor discards rows at random. Smoothing
            // still does the job it was for: 1/1 scores 0.50 and loses to 8/10 at
            // 0.73, while 3/3 scores 0.75 and beats 1/5 at 0.17.
            if p.advs >= 1 && (best.2.is_empty() || p.rsp * (best.1 + 1) > best.0 * (p.advs + 1)) {
                best = (p.rsp, p.advs, t.name);
            }
        }
        if !best.2.is_empty() {
            ulogf!("turnaround winner: {} at {}/{}\r\n", best.2, best.0, best.1);
        }
        radio_ensure_disabled();
        radio_configure_ble();
    } else if conn.ev_addr != 0 {
        // Only worth sending into a link we know is alive. `LL_TERMINATE_IND`
        // into silence just spends events on a peer that is not listening.
        terminate(&mut conn).await;
    }

    // A connection that produced no services taught us nothing about this peer,
    // so it gets the short retry cooldown rather than the full hour. That
    // distinction is what keeps the ~38% of attempts that come back silent from
    // permanently removing those devices from the rotation.
    if services > 0 {
        mark_attempted(cand.addr, Instant::now(), RECENT_WINDOW_S);
        ulogf!("enumeration complete\r\n");
        led::solid(led::OFF);
    } else {
        mark_attempted(cand.addr, Instant::now(), RETRY_COOLDOWN_S);
        ulogf!("[ERR] no services — retry after {}s\r\n", RETRY_COOLDOWN_S);
        Timer::after_millis(led::blink(led::YELLOW, 3, 60, 60)).await;
    }
}
