//! Passive connection following.
//!
//! When the advertising sniffer ([`crate::mode::ble_sniff`]) catches a `CONNECT_IND`,
//! it hands the parsed [`ConnSpec`] here. We retune the RADIO to the
//! connection's Access Address / CRCInit and hop the 37 data channels in
//! lockstep with the two peers (Channel Selection Algorithm #1), capturing both
//! the central's packet and the peripheral's T_IFS reply each connection event.
//!
//! To stay locked on real devices — which routinely renegotiate the link within
//! the first second — we parse and apply the two LL control PDUs that change the
//! timeline: `LL_CONNECTION_UPDATE_IND` (interval / window / timeout) and
//! `LL_CHANNEL_MAP_IND` (channel map), each at its effective connection event
//! (`Instant`). Following stops on `LL_TERMINATE_IND` or after
//! `supervisionTimeout / connInterval` consecutive missed events — the same two
//! conditions that end the link for the peers themselves. There is no wall-clock
//! cap: a live connection is followed for as long as it lives, so advertising
//! discovery is suspended for that whole time. The miss counter is what bounds
//! it, and it fills the moment the link goes quiet, including when the
//! `LL_TERMINATE_IND` that ended it was encrypted and therefore invisible to us.
//!
//! That counter reports under two names, because it is reached by two failures
//! that need opposite fixes. `reason=supervision` is silence after a clean lock:
//! the connection ended and we followed it to the end. `reason=desync` is the
//! counter filling while the link is provably still on air — we never locked at
//! all, or the Access Address kept matching through the outage — which is a bug
//! in our timeline, not the end of a connection.
//!
//! Timing is anchored to the *actual* master packet each event: we measure its
//! air-start (`END` timestamp − air duration) and schedule the next event a
//! `connInterval` later, which keeps the timeline drift-free.
//!
//! A connection update breaks that chain for exactly one event: its `WinOffset`
//! moves the instant event's anchor forward by `1.25 ms + WinOffset × 1.25 ms`
//! (Core v5.4 Vol 6 Part B §5.1.1), the same construction as the first anchor
//! after `CONNECT_IND`, and only `WinSize` of width is left to hunt across. The
//! offset has to move the anchor rather than widen the window: receive windows
//! are capped below one interval (see below), and a `WinOffset` of 6.25 ms on a
//! 7.5 ms interval is outside any legal window — the instant would be missed,
//! and `anchor` would then sit a whole interval behind the event counter, which
//! puts every subsequent event on the previous event's channel.
//!
//! Until the first packet lands there is nothing to re-anchor *to*, and a
//! mispredicted first anchor is self-perpetuating — the window sits in the wrong
//! place, nothing is received, so nothing corrects it, all the way to supervision
//! timeout. So the follower starts in **hunt mode**, with a receive window
//! widened to span the whole transmit window plus [`HUNT_TAIL_US`] of slop.
//!
//! That widening is deliberately *bounded*, and must stay so. An earlier
//! revision hunted by listening for a whole `connInterval`, on the reasoning
//! that a window one interval wide has to contain the master's one transmission
//! per interval. It does — but on the **wrong channel**. The master hops every
//! event, so a window that runs from `anchor[N]` to `anchor[N+1]` catches
//! event *N+1* while the radio is tuned to event *N*'s channel. When the
//! prediction is even slightly late (it was, by 368 µs) every event slips into
//! the next slot and the mismatch is self-consistent forever: captures showed
//! 0 packets in 24 events on a 24-channel map, and exactly 2 on an 8-channel
//! map — the hit rate you get from remap collisions alone. Widen far enough to
//! cover anchor error, never far enough to reach the next event.
//!
//! The `synced @ev=… offset=…us` line reports how far off the prediction was.
//!
//! Capture and decode run in separate tasks. The follow loop copies each PDU
//! into [`RX_QUEUE`] and reads only what it must act on before the next event —
//! the timeline updates above — while [`log_task`] walks the rest of the stack
//! (LL control parameters, L2CAP, ATT/SMP/LE signalling) between events. Every
//! line a packet produces is stamped with that packet's air time, so the log
//! stays ordered by when packets aired.
//!
//! `LL_PHY_UPDATE_IND` is applied at its instant too, switching the RADIO
//! between the 1M and 2M uncoded PHYs. Only a symmetric switch is followed: one
//! radio has one MODE, and an asymmetric link would need it rewritten inside the
//! 150 µs hardware turnaround between the master's packet and the reply. An
//! asymmetric or Coded switch ends the follow (`reason=phy-unsupported`) rather
//! than spending the supervision timeout listening on a PHY the peers have left.
//!
//! Limitation: once encryption starts, payloads are ciphertext (we have no
//! keys), so from there on a packet gets its header line decoded and its body
//! dumped raw rather than mis-parsed as LL/L2CAP. The boundary is caught two ways:
//! the plaintext `LL_ENC_RSP`/`LL_START_ENC` PDUs latch it directly, and — since
//! those can be missed on a link that is already renegotiating — seeing the
//! `LL_ENC_REQ` that opens the handshake arms a grace fallback that latches a
//! couple of events later regardless (see [`EncState`]). The ciphertext bytes are
//! still kept: they are the whole record of the link from that point and offline
//! decryption needs them.

use core::fmt::Write;
use core::future::pending;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Instant, Timer};

use super::{Ctx, Mode};
use crate::hal::csa2;
use crate::hal::radio::{
    arm_rxen_after, configure_ble, data_ch_freq, disarm_rxen, ensure_disabled, set_access_address,
    set_pcnf0, ADV_CRC_POLY,
};
use crate::decoder::protocol::{l2cap, ll};
use crate::decoder::{parse_connect_ind, ConnSpec};
use crate::led::{Gpio, OnBoardLed};
use crate::{led, SyncBuf};

// ── Tunables ──────────────────────────────────────────────────────────────────

const T_IFS_US: u16 = 150; // inter-frame spacing enforced by the RADIO

/// Open RX this long *before* the predicted anchor.
///
/// Has to cover everything that makes the prediction late rather than early:
/// radio ramp-up, and above all the software latency baked into `connect_end` —
/// that instant comes from a poll loop noticing `EVENTS_END`, not from a
/// hardware capture, and the CONNECT_IND decode/log runs before `follow()` is
/// even entered. Measured on hardware, the master's first packet arrived
/// **368 µs before** the predicted anchor, so the old 200 µs lead missed it by
/// ~170 µs. Drift between re-anchors is negligible by comparison (500 ppm over
/// 30 ms ≈ 15 µs).
const RX_LEAD_US: u64 = 1200;

/// How long past the predicted anchor to keep polling for the master packet,
/// once locked. Total locked window is `RX_LEAD_US + MASTER_TAIL_US`.
const MASTER_TAIL_US: u64 = 1500;

/// Extra tail added until the first packet lands, on top of the transmit-window
/// widening. See the module note on hunt mode for why this is a *bounded*
/// widening and not a whole connection interval.
const HUNT_TAIL_US: u64 = 2500;

/// Consecutive misses after which a locked follower drops back into hunt mode.
///
/// Low on purpose. A miss while locked is already abnormal — the anchor is
/// re-derived from the master's own air-start every event, so two in a row means
/// the prediction is wrong rather than the packet unlucky, and every further
/// event spent in the narrow window is one that cannot correct it. The only cost
/// of re-hunting unnecessarily is receiver-on time.
const RESYNC_AFTER_MISSES: u32 = 2;

/// Consecutive misses after which hunt escalates to a channel *scan*.
///
/// Widening the time window (hunt) recovers a slipped anchor, but not a wrong
/// channel: if a `CHANNEL_MAP_IND` was missed, the follower hops a stale map and
/// its computed channel can be permanently wrong, so no time-widening reaches the
/// master. Past this many misses it stops trusting the map and sweeps the data
/// channels instead — one per event — until it catches a packet; a caught
/// `CHANNEL_MAP_IND` then restores the map and normal following resumes. Set well
/// above [`RESYNC_AFTER_MISSES`] so an ordinary anchor slip is fixed by plain hunt
/// first, and the scan is only the deeper, last-resort recovery.
const SCAN_AFTER_MISSES: u32 = 8;

/// Direction tags for captured PDUs. Every `Packet[N]` header carries one, so a
/// capture reads as a conversation rather than two interleaved streams: the
/// central's PDU and the peripheral's T_IFS reply are otherwise distinguishable
/// only by position on the line. Plain ASCII — these go over a serial terminal.
const DIR_C2P: &str = "C->P"; // central → peripheral (the master's packet)
const DIR_P2C: &str = "P->C"; // peripheral → central (the T_IFS reply)

const SLAVE_SPAN_US: u64 = 700; // busy-poll span for the peripheral reply after master END
const MIN_MISS_CAP: u32 = 6; // supervision floor when timeout/interval is tiny

/// PHY bit masks as they appear in the C_TO_P / P_TO_C fields of
/// LL_PHY_UPDATE_IND (Core v5.4 Vol 6 Part B §2.4.2.22). A zero field means that
/// direction is not changing.
const PHY_1M: u8 = 0x01;
const PHY_2M: u8 = 0x02;

// ── Passive listen (catch a CONNECT_IND without full decode) ──────────────────

/// Primary advertising channels: (BLE channel index for whitening, nRF FREQUENCY).
const ADV_CHANNELS: [(u8, u8); 3] = [(37, 2), (38, 26), (39, 80)];
const LISTEN_DWELL_MS: u64 = 40; // per-channel listen dwell before hopping
const LISTEN_POLL_US: u64 = 150; // yield cadence while listening (keeps USB draining)
const ADV_BLINK_US: u64 = 1000; // blue blink duration on each advertising packet

// Two EasyDMA buffers so the peripheral's reply doesn't overwrite the master
// packet before we decode it. LL data PDUs are ≤ 2-byte header + 251-byte
// payload; 258 covers the maximum with margin.
static RX_M: SyncBuf<258> = SyncBuf::new();
static RX_S: SyncBuf<258> = SyncBuf::new();

// ── Pending LL updates (applied at their Instant) ─────────────────────────────

#[derive(Clone, Copy)]
struct PendUpd {
    instant: u16,
    win_size: u8,
    win_offset: u16,
    interval: u16,
    latency: u16,
    timeout: u16,
}

#[derive(Clone, Copy)]
struct PendMap {
    instant: u16,
    chm: [u8; 5],
}

#[derive(Clone, Copy)]
struct PendPhy {
    instant: u16,
    /// PHY masks from LL_PHY_UPDATE_IND, one per direction. A zero means that
    /// direction keeps the PHY it is already on.
    c_to_p: u8,
    p_to_c: u8,
}

/// Why following ended — reported on the closing `FOLLOW end` line.
enum EndReason {
    Terminate,
    Supervision,
    Desync,
    BadChannel,
    PhyUnsupported,
}

/// True once the connection event counter has reached or passed `instant`,
/// wrap-safe over the 16-bit counter. An update's instant is always scheduled a
/// small number of events ahead (< 2^15), so a half-range window separates "not
/// yet" from "reached or skipped past".
fn reached(ev: u16, instant: u16) -> bool {
    ev.wrapping_sub(instant) < 0x8000
}

// ── CSA#1 ─────────────────────────────────────────────────────────────────────

/// Channel Selection Algorithm #1: map an unmapped channel index (0..36) through
/// the connection's channel map to a `(channel index, nRF frequency)` pair. A
/// channel that is in the map is used directly; otherwise it is remapped onto the
/// `unmapped % used_count`-th enabled channel. Returns `None` if the map is empty
/// or the index doesn't resolve to a valid data channel.
fn csa1_channel(unmapped: u8, chm: &[u8; 5]) -> Option<(u8, u8)> {
    let used = |idx: u8| chm[(idx / 8) as usize] & (1 << (idx % 8)) != 0;
    if used(unmapped) {
        return data_ch_freq(unmapped).map(|f| (unmapped, f));
    }
    let count: u32 = chm.iter().map(|b| b.count_ones()).sum();
    if count == 0 {
        return None;
    }
    let target = (unmapped as u32 % count) as u8;
    let mut k = 0u8;
    for idx in 0..37u8 {
        if used(idx) {
            if k == target {
                return data_ch_freq(idx).map(|f| (idx, f));
            }
            k += 1;
        }
    }
    None
}

// CSA#2 (channel selection) now lives in `common` — shared with periodic-sync
// following in `ble_sniff`. See `hal::csa2::channel` / `hal::csa2::chan_id`.

// ── Dedicated mode entry ──────────────────────────────────────────────────────

/// Passive connection-follower mode: listen for a `CONNECT_IND` on the primary
/// advertising channels, follow that connection onto the data channels until it
/// ends (terminate / supervision timeout / cap), then repeat forever.
///
/// Owns the onboard LED directly as GPIO (this mode does not run the shared
/// `led::indicator` task, whose PWM update busy-waits a PWM period). Between
/// follows it blinks blue on each advertising packet seen; during a follow the
/// colour reports lock — blue while the timeline is tracking, red on an event we
/// missed — with a green flash for each connection event that carried data. A
/// follow always exits back to the blue blink.
pub async fn run(mut leds: impl led::ChanSink) {
    loop {
        // All off while we hunt for the next CONNECT_IND.
        leds.set(led::OFF);

        let (spec, connect_end) = listen_for_connect_ind(&mut leds).await;
        follow(&spec, connect_end, &mut leds).await;
    }
}

/// Passively scan the advertising channels until a `CONNECT_IND` is captured,
/// returning its parsed [`ConnSpec`] and the `EVENTS_END` timestamp of the PDU
/// (the connection timeline anchors on it). Blinks blue for ~1 ms on every
/// advertising packet received so activity is visible.
///
/// Re-arms the advertising AA/CRC via [`configure_ble`] at entry, which
/// also undoes the connection-specific AA a previous [`follow`] left behind (so
/// the receiver isn't wedged on the wrong access address).
async fn listen_for_connect_ind(leds: &mut impl led::ChanSink) -> (ConnSpec, Instant) {
    let r = pac::RADIO;
    configure_ble();
    let mut blue_off: Option<Instant> = None;

    loop {
        for &(ch_idx, freq) in ADV_CHANNELS.iter() {
            ensure_disabled();
            r.frequency().write(|w| { w.set_frequency(freq); w.set_map(vals::Map::Default); });
            r.datawhiteiv().write(|w| w.set_datawhiteiv(ch_idx));
            r.packetptr().write_value(RX_M.0.get() as u32);
            r.events_end().write_value(0);
            r.events_crcok().write_value(0);
            r.events_address().write_value(0);
            r.events_disabled().write_value(0);
            r.shorts().write(|w| {
                w.set_rxready_start(true);
                w.set_address_rssistart(true);
            });
            r.tasks_rxen().write_value(1);

            let deadline = Instant::now() + Duration::from_millis(LISTEN_DWELL_MS);
            loop {
                // Retire an expired blue blink without blocking the receiver.
                if let Some(t) = blue_off
                    && Instant::now() >= t
                {
                    leds.set_chan(led::Chan::B, false);
                    blue_off = None;
                }

                if r.events_end().read() != 0 {
                    r.events_end().write_value(0);
                    let t_end = Instant::now();
                    // EVENTS_CRCOK is a latch, not a per-packet flag: the radio
                    // sets it and never clears it. Since this loop re-arms with
                    // TASKS_START and keeps reading, it MUST be cleared here —
                    // otherwise the first good packet of the dwell latches it and
                    // every later reception, CRC failures included, is accepted
                    // as valid. That is how corrupted noise reached the
                    // CONNECT_IND parser and produced 79-second "intervals".
                    let crc_ok = r.events_crcok().read() != 0;
                    r.events_crcok().write_value(0);
                    r.events_address().write_value(0);
                    if crc_ok {
                        // Advertising packet received → blink blue.
                        leds.set_chan(led::Chan::B, true);
                        blue_off = Some(Instant::now() + Duration::from_micros(ADV_BLINK_US));

                        let buf = unsafe { &*RX_M.0.get() };
                        let pdu_type = buf[0] & 0x0F;
                        let length = buf[1] as usize;
                        if pdu_type == 0x05 && length >= 34 {
                            let payload_len = length.min(buf.len() - 2);
                            if let Some(spec) = parse_connect_ind(buf[0], &buf[2..2 + payload_len]) {
                                // Second gate: a CONNECT_IND we cannot follow is
                                // worse than none at all — we would commit the
                                // radio to a timeline derived from nonsense and
                                // sit there until the event cap. See
                                // [`ConnSpec::is_followable`].
                                if !spec.is_followable() {
                                    ulogf!(
                                        "[ERR] ignored malformed CONNECT_IND ch={} aa=0x{:08X} interval={} hop={} timeout={}\r\n",
                                        ch_idx, spec.aa, spec.interval, spec.hop, spec.timeout
                                    );
                                    r.tasks_start().write_value(1);
                                    continue;
                                }
                                ulogf!("CONNECT_IND ch={} aa=0x{:08X}\r\n", ch_idx, spec.aa);
                                crate::decoder::decode_connect_ind(buf[0], &buf[2..2 + payload_len]);
                                disable_radio();
                                leds.set_chan(led::Chan::B, false);
                                return (spec, t_end);
                            }
                        }
                    }
                    // Not our trigger — re-arm reception on this channel.
                    r.tasks_start().write_value(1);
                }

                if Instant::now() >= deadline {
                    break;
                }
                Timer::after_micros(LISTEN_POLL_US).await;
            }

            disable_radio();
        }
    }
}

/// Clear SHORTS and force the radio to DISABLED (busy-wait). Used between listen
/// channels and before handing off to [`follow`].
fn disable_radio() {
    let r = pac::RADIO;
    r.shorts().write(|_w| {});
    r.tasks_disable().write_value(1);
    while r.events_disabled().read() == 0 {}
    r.events_disabled().write_value(0);
}

// ── Follow ────────────────────────────────────────────────────────────────────

/// Follow the connection described by `spec` starting from `connect_end` (the
/// `EVENTS_END` timestamp of the `CONNECT_IND` that opened it). Owns the radio
/// until it stops; the caller's advertising scan resumes afterwards.
///
/// The LED carries lock state and traffic on separate channels: blue for an
/// event we captured, red for one we missed — held until the next event resolves,
/// so an outage reads as solid red and a single dropped event as one blink — plus
/// a green flash for an event that carried a payload. On exit the LED is cleared
/// and the advertising AA/CRC restored, so a subsequent listen isn't wedged on
/// the connection's AA.
pub async fn follow(
    spec: &ConnSpec,
    connect_end: Instant,
    leds: &mut impl led::ChanSink,
) {
    // Live link state — mutated as LL control PDUs are applied.
    let mut interval = spec.interval;
    let mut timeout = spec.timeout;
    let mut chm = spec.chm;
    // Kept live (not just read once from `spec`) because re-hunting after a lost
    // lock rebuilds the widened window from it, and a connection update may have
    // changed it since.
    let mut win_size = spec.win_size;
    let hop = spec.hop;
    // Seed for the CSA#2 sequence, fixed for the connection. Computed for every
    // link so the `csa=1` path costs one XOR and the branch below reads the same
    // either way.
    let chan_id = csa2::chan_id(spec.aa);

    ulogf!(
        "  FOLLOW aa=0x{:08X} crcinit=0x{:06X} interval={}.{:02}ms csa={} hop={} chmap={:02X}{:02X}{:02X}{:02X}{:02X} start\r\n",
        spec.aa, spec.crc_init,
        (interval as u32 * 125) / 100, (interval as u32 * 125) % 100,
        if spec.csa2 { 2 } else { 1 }, hop,
        chm[0], chm[1], chm[2], chm[3], chm[4]
    );

    configure_radio(spec.aa, spec.crc_init);

    // First anchor = connEnd + transmitWindowDelay (1.25 ms) + WinOffset·1.25 ms.
    // The master's first packet may land anywhere in the transmit window, so this
    // event uses a widened receive span.
    let mut anchor = connect_end
        + Duration::from_micros(1250 + spec.win_offset as u64 * 1250);
    // The transmit window is the dominant unknown for as long as we haven't
    // locked, so hunt mode re-applies it every event; `wide_us` is the one-shot
    // version, consumed by the first event and re-armed by connection updates.
    let mut hunt_wide_us = (win_size as u64 + 1) * 1250;
    let mut wide_us = hunt_wide_us;

    // Events since the follow began, counted without wrapping so the log can
    // report a total. The link layer's own connection event counter is 16 bits
    // and does wrap; the three places that need that counter — the `instant`
    // comparisons below and CSA#2 channel selection — truncate to `u16` at the
    // point of use. A follow long enough to overflow this would have to run for
    // a year at the shortest legal interval.
    let mut ev: u32 = 0;
    let mut unmapped: u8 = 0;
    let mut consec_miss: u32 = 0;
    // Data channel the scan recovery listens on, swept one per event once the miss
    // run passes [`SCAN_AFTER_MISSES`]; see the channel-selection block below.
    let mut scan_ch: u8 = 0;
    // Did the Access Address match anywhere in the *current* run of misses?
    // Cleared by every captured event, so it describes the outage in progress
    // rather than the whole follow. This is what separates a link that ended
    // from one we can hear but no longer hold — see the supervision break.
    let mut outage_addr = false;
    // Monotonic across this connection only, so the last `Packet[N]` equals
    // `master + slave - empty` on the FOLLOW end line: the keepalives counted in
    // `empty` are received but never queued or numbered.
    let mut pkt_no: u32 = 0;
    // Encryption tracking, per connection (clears on the next). Once `on`, every
    // captured payload is ciphertext.
    let mut enc = EncState::default();
    // Locked onto the real timeline? Until the first master packet is captured
    // the anchor is only a *prediction* derived from `connect_end`, and the
    // re-anchoring in the capture path can never fix an error in it: correcting
    // the anchor needs a reception, and a reception needs the window to already
    // be in the right place. So stay in hunt mode until the first hit.
    let mut synced = false;
    // Diagnostics for the closing line — without these a failed follow reports
    // only "supervision", which says nothing about *how* it failed.
    let mut n_m: u32 = 0; // events where a master packet was captured
    let mut n_s: u32 = 0; // …that also yielded the peripheral's reply
    let mut n_empty: u32 = 0; // empty PDUs seen — the keepalives capture() drops undecoded
    let mut n_addr: u32 = 0; // events where EVENTS_ADDRESS fired (AA matched)
    let mut n_crc: u32 = 0; // …and the packet passed CRC
    // Miss breakdown, the two failures that need opposite fixes. A miss where
    // EVENTS_ADDRESS fired means we were on the right channel at the right time and
    // lost the packet mid-air (reception / window tail). A *silent* miss saw no
    // Access-Address match at all — wrong channel, a window that didn't span the
    // master's transmission, or a signal below detection. The master transmits
    // every connection event, so a silent miss is never the peer staying quiet.
    let mut n_miss_addr: u32 = 0;
    let mut n_miss_silent: u32 = 0;
    // Whether the link has locked at least once. Gates per-miss logging: before
    // the first lock, hunt-mode misses are expected and would only be noise.
    let mut ever_synced = false;
    // Locks regained after an outage. Each one proves the peers were still
    // exchanging packets long after we started missing them, which is the
    // difference between a link that ended and a timeline that drifted.
    let mut n_relock: u32 = 0;
    // Achieved lead before each RX window opened (see `lead_us`). `first_` is the
    // first event's — dominated by the transmit-window offset it waits out, so it
    // is large and positive by construction and says nothing about tracking.
    // `min_` is the worst lead across the follow and is the real scheduling
    // signal: negative means a window opened late because setup fell behind the
    // clock, which loses the packet on a correctly selected channel.
    let mut first_lead_us = i32::MIN;
    let mut min_lead_us = i32::MAX;
    // The same figures restricted to events that missed. `first_/min_lead` cover
    // every event, while the per-event `miss @ev=… lead=` line prints only on the
    // miss path — reading one against the other compares two different
    // populations. These make the miss population directly comparable.
    let mut miss_lead_min_us = i32::MAX;
    let mut miss_lead_max_us = i32::MIN;
    // Supervision budget: how many consecutive events may be missed before the
    // link is presumed lost. supervisionTimeout / connInterval, with a floor.
    // Recomputed whenever a connection update changes the interval/timeout.
    let supervision_cap = |to: u16, iv: u16| ((to as u32 * 10 * 1000) / (iv as u32 * 1250)).max(MIN_MISS_CAP);
    let mut miss_cap = supervision_cap(timeout, interval);

    let mut pending_upd: Option<PendUpd> = None;
    let mut pending_map: Option<PendMap> = None;
    let mut pending_phy: Option<PendPhy> = None;
    // Symmetric by construction: an asymmetric LL_PHY_UPDATE_IND ends the follow
    // below, so one variable covers both directions. Feeds `air_us`, which the
    // re-anchor depends on — a stale PHY here walks the anchor off by the air
    // time difference every event.
    let mut phy = PHY_1M;

    let r = pac::RADIO;
    let reason;

    loop {
        // Retire the previous event's green flash. The blue/red base colour is
        // left alone until this event resolves: clearing it here would blank the
        // LED for the whole inter-event gap and turn a state into a flicker.
        leds.set_chan(led::Chan::G, false);

        // Apply any update scheduled for this event, before hopping / windowing.
        if let Some(u) = pending_upd
            && u.instant == ev as u16
        {
            interval = u.interval;
            timeout = u.timeout;
            miss_cap = supervision_cap(timeout, interval);
            let _ = u.latency; // latency doesn't affect passive capture
            win_size = u.win_size;
            // WinOffset moves this event's anchor, it does not widen its window.
            // The master's first packet under the new parameters lands in a
            // transmit window opening transmitWindowDelay (1.25 ms) + WinOffset
            // × 1.25 ms after where the instant event sat under the old interval
            // (Core v5.4 Vol 6 Part B §5.1.1) — the same construction as the
            // first anchor after CONNECT_IND. Listening early and waiting it out
            // instead only reaches the packet while the offset fits inside the
            // span cap of three quarters of an interval, and a WinOffset of
            // 6.25 ms on a 7.5 ms interval does not: the instant is missed and
            // `anchor` is then a whole new interval behind the event counter, so
            // every channel from there on is the previous event's.
            anchor += Duration::from_micros(1250 + u.win_offset as u64 * 1250);
            // Anchored on the window's start, only its width is still unknown.
            wide_us = (u.win_size as u64 + 1) * 1250;
            pending_upd = None;
            ulogf!("    applied CONNECTION_UPDATE @ev={} interval={}.{:02}ms anchor+{}us\r\n",
                ev, (interval as u32 * 125) / 100, (interval as u32 * 125) % 100,
                1250 + u.win_offset as u64 * 1250);
        }
        // The radio is disabled here (`cleanup_radio` ran at the end of the
        // previous event), which is the only point in the loop where MODE may
        // be rewritten.
        if let Some(p) = pending_phy
            && p.instant == ev as u16
        {
            phy = if p.c_to_p != 0 { p.c_to_p } else { p.p_to_c };
            pending_phy = None;
            set_phy(phy);
            // Losing the anchor's air-time basis is the same failure as losing
            // the channel, so drop back to hunt mode for one event rather than
            // trusting a window sized for the old PHY.
            synced = false;
            hunt_wide_us = (win_size as u64 + 1) * 1250;
            ulogf!("    applied PHY_UPDATE @ev={} phy={}\r\n", ev, phy_name(phy));
        }

        // Phase-preserving catch-up. Everything below assumes `anchor` is still
        // ahead of the clock. If an event overran its interval, sliding one
        // event late would tune every window from here on to the *previous*
        // event's channel while the master is already on the next one — a
        // mismatch that is self-consistent and never recovers. Skip whole
        // intervals instead, advancing the event index and the hop with them, so
        // time and channel stay in step.
        let interval_us = Duration::from_micros(interval as u64 * 1250);
        let floor = Instant::now() + Duration::from_micros(RX_LEAD_US);
        let mut skipped = 0u32;
        while anchor < floor {
            anchor += interval_us;
            if !spec.csa2 {
                unmapped = (unmapped + hop) % 37;
            }
            ev = ev.wrapping_add(1);
            skipped += 1;
        }
        if skipped > 0 {
            ulogf!("    [ERR] anchor was {} event(s) behind the clock, skipped to ev={}\r\n", skipped, ev);
        }

        // Apply a pending channel map here — after the catch-up loop, and keyed on
        // the event counter having *reached* the instant rather than equalling it.
        // Applying it before catch-up (as the connection/PHY updates still are) let a
        // map whose instant fell on a skipped event slip through unapplied, leaving
        // the follower hopping a stale map for the rest of the connection. A busy
        // central re-runs AFH every few seconds, so a single dropped map is the
        // difference between following and a supervision-timeout outage.
        if let Some(m) = pending_map
            && reached(ev as u16, m.instant)
        {
            chm = m.chm;
            pending_map = None;
            ulogf!("    applied CHANNEL_MAP @ev={} chmap={:02X}{:02X}{:02X}{:02X}{:02X}\r\n",
                ev, chm[0], chm[1], chm[2], chm[3], chm[4]);
        }

        // The CSA#1 unmapped index advances one hop every event — including the
        // events catch-up skipped (above) and the scan events below — so that once
        // the follower resyncs the hop is already in step with the peers.
        if !spec.csa2 {
            unmapped = (unmapped + hop) % 37;
        }

        // This event's channel. Normally CSA#2 reads it off the event counter and
        // CSA#1 remaps its unmapped index through the map. But once a miss run passes
        // `SCAN_AFTER_MISSES` the map is no longer trusted (a dropped CHANNEL_MAP_IND
        // makes the computed channel permanently wrong): sweep the 37 data channels
        // one per event instead, so we eventually land on the master and — catching
        // a CHANNEL_MAP_IND — restore the map. `ever_synced` gates this so it is only
        // a *recovery*, never the initial acquisition (which the hunt window covers).
        let scanning = ever_synced && !synced && consec_miss >= SCAN_AFTER_MISSES;
        let selected = if scanning {
            scan_ch = (scan_ch + 1) % 37;
            data_ch_freq(scan_ch).map(|f| (scan_ch, f))
        } else if spec.csa2 {
            csa2::channel(ev as u16, chan_id, &chm)
        } else {
            csa1_channel(unmapped, &chm)
        };
        let (ch, freq) = match selected {
            Some(cf) => cf,
            None => { reason = EndReason::BadChannel; break; }
        };
        // Announce the escalation once per outage, at the event it begins.
        if scanning && consec_miss == SCAN_AFTER_MISSES {
            ulogf!("    scanning channels to re-acquire @ev={}\r\n", ev);
        }

        // Window = RX_LEAD_US before the anchor + a tail after it. While hunting
        // the tail stays widened every event (not one-shot): the prediction is
        // still uncorrected, so every event needs the slop, not just the first.
        // It is capped well short of the next anchor — see the module note.
        let tail = if synced {
            MASTER_TAIL_US + wide_us
        } else {
            MASTER_TAIL_US + HUNT_TAIL_US + hunt_wide_us
        };
        wide_us = 0; // one-shot: the update's transmit window applies to one event
        // Cap at three quarters of the interval, never the whole thing. `.min(
        // interval)` was the old cap and it permits precisely the failure the
        // module note describes: a window reaching anchor[N+1] receives the next
        // event on this event's channel. Short intervals are where it bites —
        // at 7.5 ms the hunt tail alone already exceeds one interval.
        let span = (RX_LEAD_US + tail).min(interval as u64 * 1250 * 3 / 4);
        let rx_open = anchor - Duration::from_micros(RX_LEAD_US);
        // Achieved lead: how much slack there actually was before RX opened.
        // Negative means the anchor was already in the past when we got here —
        // the window is late by that much and only the tail is protecting us.
        let now = Instant::now();
        let lead_us = match rx_open.checked_duration_since(now) {
            Some(d) => d.as_micros() as i32,
            None => -(now.duration_since(rx_open).as_micros() as i32),
        };
        if first_lead_us == i32::MIN {
            first_lead_us = lead_us;
        }
        min_lead_us = min_lead_us.min(lead_us);
        // Configure the receive window *before* waiting it out, then hardware-arm
        // RXEN to fire at rx_open through TIMER1+PPI. The wait yields to the
        // executor, where log_task decodes queued PDUs and drains USB; a software
        // tasks_rxen issued after the wait fires only when this task is next
        // scheduled — late by however long that drain ran — and RX then opened
        // after the master had already aired. That is the silent miss: two in a
        // row drop the lock, and the same late window is why hunt often failed to
        // relock and why the peripheral's turnaround reply was lost. The hardware
        // trigger opens RX at the scheduled instant no matter what the CPU is
        // doing; EVENTS_END latches, so even a late wake reads the packet.
        ensure_disabled();
        r.frequency().write(|w| { w.set_frequency(freq); w.set_map(vals::Map::Default); });
        r.datawhiteiv().write(|w| w.set_datawhiteiv(ch));
        r.packetptr().write_value(RX_M.0.get() as u32);
        r.events_end().write_value(0);
        r.events_crcok().write_value(0);
        r.events_address().write_value(0);
        r.events_disabled().write_value(0);
        // On each packet END: disable, re-enable RX, restart — auto-catches the
        // peripheral's reply T_IFS later on the same channel.
        r.shorts().write(|w| {
            w.set_rxready_start(true);
            w.set_end_disable(true);
            w.set_disabled_rxen(true);
            w.set_address_rssistart(true);
        });
        // lead_us is non-negative here: the catch-up loop above guarantees
        // anchor ≥ now + RX_LEAD_US, so rx_open ≥ now. A lead inside
        // RXEN_MIN_LEAD_US fires immediately inside the helper.
        arm_rxen_after(lead_us.max(0) as u32);
        // Wait out the pre-anchor lead (yields to the executor so USB drains),
        // then busy-poll the reception window at µs precision. RX is already
        // opening on the hardware trigger while this waits.
        Timer::at(rx_open).await;

        // ── Master packet ────────────────────────────────────────────────────
        let rx_opened = Instant::now();
        let m_deadline = rx_opened + Duration::from_micros(span);
        let mut got_m = false;
        let mut t_m_end = Instant::now();
        while Instant::now() < m_deadline {
            if r.events_end().read() != 0 {
                r.events_end().write_value(0);
                t_m_end = Instant::now();
                // Redirect the (already re-arming) RX to the second buffer so the
                // reply doesn't clobber the master packet. PACKETPTR latches at
                // the next START, which the shorts chain hasn't reached yet.
                r.packetptr().write_value(RX_S.0.get() as u32);
                got_m = true;
                break;
            }
        }

        if !got_m {
            // Missed: red alone, and it stays lit until an event is captured.
            leds.set(led::RED);
            // Read the reception flags *before* cleanup clears them.
            let addr_seen = r.events_address().read() != 0;
            if addr_seen {
                n_addr += 1;
                n_miss_addr += 1;
                outage_addr = true;
            } else {
                n_miss_silent += 1;
            }
            cleanup_radio();
            consec_miss += 1;
            miss_lead_min_us = miss_lead_min_us.min(lead_us);
            miss_lead_max_us = miss_lead_max_us.max(lead_us);
            // One line per missed event once the link has locked at least once, so
            // a run of misses shows *where* (channel) and *why* (ADDR vs silent,
            // and how late the window opened) rather than only that it happened.
            // `lead_us` is that event's own achieved lead: negative here alongside
            // a silent miss points at a late window, not a channel error.
            //
            // Every miss while still locked, then one in 64: a desynced follower
            // on a 7.5 ms interval produces ~130 of these a second and thousands
            // per outage, which buries the packets and puts formatting work in
            // every event. The `lost lock` line below marks where each run began
            // and `miss_addr` / `miss_silent` on the closing line count them all.
            if ever_synced && (synced || consec_miss.is_multiple_of(64)) {
                ulogf!(
                    "    miss @ev={} ch={} lead={}us {}\r\n",
                    ev, ch, lead_us,
                    if addr_seen { "on-channel (ADDR, no END)" } else { "silent (no ADDR)" }
                );
            }
            // Fall back into hunt mode after a short run of misses.
            //
            // `synced` used to be a one-way latch: the first capture narrowed the
            // window to [-RX_LEAD_US, +MASTER_TAIL_US] permanently. If the anchor
            // ever slipped outside that ~2.7 ms — a connection update we failed to
            // parse, a master that re-anchors on its own schedule, an event whose
            // first packet we missed so we re-anchored on a later one — nothing
            // could ever widen it again, because widening only happened before the
            // first capture. The follower then missed every remaining event at a
            // fixed offset and died on supervision timeout with the channel
            // sequence perfectly correct. Observed directly: locked at ev1,
            // recaptured at ev7 with the offset having moved 1463 µs, then 24
            // consecutive misses to timeout.
            //
            // Re-hunting costs only receiver-on time, and the window stays bounded
            // below one interval, so it cannot stray onto the next event.
            if synced && consec_miss >= RESYNC_AFTER_MISSES {
                synced = false;
                hunt_wide_us = (win_size as u64 + 1) * 1250;
                // One line per outage, not per missed event. Without it an idle
                // link that we are following correctly and a link we have gone
                // deaf to both log nothing at all, and the `synced @ev=` line
                // that follows would look like a first lock rather than a
                // recovery. `addr_seen` distinguishes right-channel-right-time
                // with the packet lost mid-air from hearing nothing whatsoever.
                ulogf!(
                    "    lost lock @ev={} ch={} after {} misses{}\r\n",
                    ev, ch, consec_miss,
                    if addr_seen { " (ADDR-no-END: on channel, losing packets)" } else { "" }
                );
            }
            if consec_miss >= miss_cap {
                // Two different failures reach the same counter, and the closing
                // line is the only place they can be told apart. If we never
                // locked at all, or the Access Address kept matching right
                // through the outage, the link is demonstrably still on air and
                // it is our timeline that failed. Total silence after a clean
                // lock is indistinguishable from the peers ending the
                // connection — an encrypted `LL_TERMINATE_IND` reads exactly
                // like a peer walking out of range — so that case keeps the
                // supervision label the peers themselves would apply.
                //
                // Earlier relocks are deliberately not a witness here. They say
                // the link survived an *earlier* outage, not this one, and this
                // one has by now run a full supervision timeout — long enough
                // that the peers gave up too. `relock=` on the closing line is
                // where a follow that flapped its way here is visible.
                reason = if !ever_synced || outage_addr {
                    EndReason::Desync
                } else {
                    EndReason::Supervision
                };
                break;
            }
            anchor += interval_us;
            ev = ev.wrapping_add(1);
            continue;
        }
        consec_miss = 0;
        outage_addr = false;
        n_m += 1;
        n_addr += 1;
        let crc_m = r.events_crcok().read() != 0;
        if crc_m {
            n_crc += 1;
        }
        // Still read for the re-anchor below, which needs its air time.
        let len_m = unsafe { (*RX_M.0.get())[1] };
        // Captured, so the base colour goes back to blue for this event.
        leds.set_chan(led::Chan::R, false);
        leds.set_chan(led::Chan::B, true);

        // ── Peripheral reply ─────────────────────────────────────────────────
        r.events_end().write_value(0);
        r.events_crcok().write_value(0);
        let s_deadline = Instant::now() + Duration::from_micros(SLAVE_SPAN_US);
        let mut got_s = false;
        let mut t_s_end = Instant::now();
        while Instant::now() < s_deadline {
            if r.events_end().read() != 0 {
                r.events_end().write_value(0);
                t_s_end = Instant::now();
                got_s = true;
                break;
            }
        }
        let crc_s = got_s && r.events_crcok().read() != 0;
        let len_s = if got_s { unsafe { (*RX_S.0.get())[1] } } else { 0 };

        cleanup_radio();

        // Green flashes on a connection event that carried a payload. Every event
        // has a master packet and on an idle link nearly all of them are empty
        // PDUs, so flashing on all of them would hold the LED cyan whenever the
        // follow is healthy and say nothing about traffic; this way the flashes
        // track the packets the log actually prints.
        if len_m != 0 || len_s != 0 {
            leds.set_chan(led::Chan::G, true);
        }

        if got_s {
            n_s += 1;
        }

        // Empty PDUs are the keepalives an idle link exchanges every event;
        // capture() drops them undecoded. Count them here with the same len==0
        // test capture() uses, so `master + slave - empty` equals the last
        // `Packet[N]`. Not CRC-gated, to match exactly what capture() omits.
        if len_m == 0 {
            n_empty += 1;
        }
        if got_s && len_s == 0 {
            n_empty += 1;
        }

        // Re-anchor to the master's actual air-start (drift-free, and absorbs any
        // transmit-window offset).
        let m_air = Duration::from_micros(air_us(phy, len_m));
        let air_start = t_m_end - m_air;
        // Where the master actually landed relative to the prediction, every
        // event — not just the first. Once locked this should hover near zero;
        // a steady drift means the interval is wrong, a jump means the peer
        // re-anchored (or we followed the wrong packet).
        let d_m_us = match air_start.checked_duration_since(anchor) {
            Some(d) => d.as_micros() as i32,
            None => -(anchor.duration_since(air_start).as_micros() as i32),
        };
        if !synced {
            if ever_synced {
                n_relock += 1;
            }
            synced = true;
            ever_synced = true;
            hunt_wide_us = 0;
            // How far the real timeline sat from the predicted one. Small values
            // (inside the transmit window, 0..winSize) are normal; anything
            // larger means the `connect_end` → anchor model is off and would
            // have been an unrecoverable blackout before hunt mode existed.
            ulogf!(
                "    synced @ev={} ch={} offset={}us len={} (window was [{},+{}]us)\r\n",
                ev, ch, d_m_us, len_m, -(RX_LEAD_US as i64), span - RX_LEAD_US
            );
        }
        anchor = air_start + interval_us;

        // ── Queue for decode + apply control ─────────────────────────────────
        // Both directions are queued in the order they aired, so the decoded
        // capture still reads as a conversation.
        let mut act = capture(DIR_C2P, ev, crc_m, air_start, RX_M.0.get(), &mut pkt_no, &mut enc);
        if got_s {
            // The reply's air-start, derived the same way as the master's: its
            // END timestamp less its own air time.
            let s_air = t_s_end - Duration::from_micros(air_us(phy, len_s));
            let s_act = capture(DIR_P2C, ev, crc_s, s_air, RX_S.0.get(), &mut pkt_no, &mut enc);
            // A control PDU from either side is applied. When both carry one the
            // peripheral's is the later of the two on air, except that a
            // termination from the central ends the link whatever answers it.
            if !matches!(act, ControlAction::Terminate) && !matches!(s_act, ControlAction::None) {
                act = s_act;
            }
        }
        match act {
            ControlAction::Terminate => { reason = EndReason::Terminate; break; }
            ControlAction::Update(u) => pending_upd = Some(u),
            ControlAction::Map(m) => pending_map = Some(m),
            ControlAction::Phy(p) => {
                // One radio, one MODE: an asymmetric switch would need the
                // PHY changed between the master's packet and the reply that
                // follows it 150 µs later, which the shorts chain does the
                // turnaround for and cannot be reprogrammed inside. Coded PHY
                // additionally needs the CI/TERM header fields. Either way
                // there is no point spending the supervision timeout hunting
                // packets we could not demodulate.
                let asym = p.c_to_p != 0 && p.p_to_c != 0 && p.c_to_p != p.p_to_c;
                let want = if p.c_to_p != 0 { p.c_to_p } else { p.p_to_c };
                if asym || (want != PHY_1M && want != PHY_2M) {
                    ulogf!(
                        "  LL_PHY_UPDATE_IND @ev={} c_to_p=0x{:02X} p_to_c=0x{:02X} — not followable\r\n",
                        ev, p.c_to_p, p.p_to_c
                    );
                    reason = EndReason::PhyUnsupported;
                    break;
                }
                pending_phy = Some(p);
            }
            ControlAction::None => {}
        }

        ev = ev.wrapping_add(1);
    }

    ensure_disabled();
    // Back to the listen state: dark until the next advertising packet blinks it
    // blue. Leaving a follow's last colour lit would report a lock that ended.
    leds.set(led::OFF);
    // Restore the advertising AA/CRC so the next listen isn't wedged on the
    // connection's access address (the bug that left the scanner dead after a
    // follow in the ble_sniff-triggered path).
    configure_ble();
    let tag = match reason {
        EndReason::Terminate => "terminate",
        EndReason::Supervision => "supervision",
        EndReason::Desync => "desync",
        EndReason::BadChannel => "bad-channel",
        EndReason::PhyUnsupported => "phy-unsupported",
    };
    drain_queue().await;
    // Sentinels mean the loop broke before a window ever opened (e.g. bad channel
    // on the first event); report 0 rather than the raw i32 extremes.
    let first_lead = if first_lead_us == i32::MIN { 0 } else { first_lead_us };
    let min_lead = if min_lead_us == i32::MAX { 0 } else { min_lead_us };
    let miss_lo = if miss_lead_min_us == i32::MAX { 0 } else { miss_lead_min_us };
    let miss_hi = if miss_lead_max_us == i32::MIN { 0 } else { miss_lead_max_us };
    ulogf!(
        "  FOLLOW end reason={} events={} master={} slave={} empty={} addr={} crcok={} dropped={} miss_addr={} miss_silent={} relock={} phy={} lead_all_first={}us lead_all_min={}us lead_miss={}..{}us\r\n",
        tag, ev, n_m, n_s, n_empty, n_addr, n_crc, DROPPED.swap(0, Ordering::Relaxed),
        n_miss_addr, n_miss_silent, n_relock, phy_name(phy), first_lead, min_lead, miss_lo, miss_hi
    );
}

/// Configure the RADIO for a data-channel connection: reuse the shared BLE
/// packet layout (PCNF0/1, CRC engine, whitening), then override the Access
/// Address and CRCInit for this connection and set the T_IFS + fast ramp needed
/// for the RX→RX turnaround.
fn configure_radio(aa: u32, crc_init: u32) {
    let r = pac::RADIO;
    ensure_disabled();
    configure_ble();
    set_access_address(aa);
    r.crcpoly().write(|w| w.set_crcpoly(ADV_CRC_POLY));
    r.crcinit().write(|w| w.set_crcinit(crc_init));
    r.tifs().write(|w| w.set_tifs(T_IFS_US));
    // Default (140 µs) ramp: hardware TIFS times from the last bit on air to
    // just after READY and is only qualified for the default ramp, so Fast
    // (40 µs) shifts the RX→RX turnaround instead of tightening it. Measured
    // 8/11 vs 4/22 replies in the `gatt.rs` turnaround sweep.
    r.modecnf0().modify(|w| w.set_ru(vals::Ru::Default));
}

/// Switch the RADIO between the 1M and 2M uncoded PHYs mid-connection. Only MODE
/// and the preamble length differ; the AA, CRC seed, whitening and T_IFS set up
/// by [`configure_radio`] carry over untouched. Called with the radio already
/// disabled, between connection events.
fn set_phy(phy: u8) {
    let r = pac::RADIO;
    ensure_disabled();
    if phy == PHY_2M {
        r.mode().write(|w| w.set_mode(vals::Mode::Ble2mbit));
        set_pcnf0(vals::Plen::_16bit);
    } else {
        r.mode().write(|w| w.set_mode(vals::Mode::Ble1mbit));
        set_pcnf0(vals::Plen::_8bit);
    }
}

/// Air time of a data PDU carrying `len` payload bytes, preamble start to last
/// CRC bit — the span subtracted from an END timestamp to recover the air-start
/// the anchor tracks. Both PHYs send AA(4) + header(2) + payload + CRC(3); 1M
/// prefixes a 1-byte preamble at 8 µs/byte, 2M a 2-byte preamble at 4 µs/byte.
fn air_us(phy: u8, len: u8) -> u64 {
    if phy == PHY_2M {
        (11 + len as u64) * 4
    } else {
        (10 + len as u64) * 8
    }
}

fn phy_name(phy: u8) -> &'static str {
    if phy == PHY_2M { "2M" } else { "1M" }
}

fn cleanup_radio() {
    let r = pac::RADIO;
    r.shorts().write(|_w| {});
    r.tasks_disable().write_value(1);
    while r.events_disabled().read() == 0 {}
    r.events_disabled().write_value(0);
    // Release the TIMER1+PPI one-shot that armed this event's RXEN. The compare
    // has already fired and stopped the timer by now; this only disables the PPI
    // channel so nothing lingers between events.
    disarm_rxen();
}

// ── Decode queue ──────────────────────────────────────────────────────────────
// Decoding a captured PDU now walks the whole stack — LL control parameters,
// L2CAP, then ATT/SMP/LE-signalling, several formatted lines each — while the
// follow loop has at most `interval` microseconds before it must be waiting on
// the next anchor. So the capture path copies the bytes here and moves on;
// [`log_task`] drains the queue and decodes while the radio is between events.
//
// Depth 8 covers the worst burst the follower can produce: both directions of an
// event, back to back, while a long service-discovery response from the previous
// event is still being formatted.
const RX_QUEUE_DEPTH: usize = 8;

/// One captured data PDU, copied out of [`RX_M`]/[`RX_S`] so the next event can
/// overwrite them before this one is decoded.
pub struct RxPdu {
    /// Air-start of the packet. Every line logged for it carries this instant —
    /// see [`crate::with_log_stamp`] — so the log stays a record of when packets
    /// aired rather than of when the decoder got to them.
    pub t_air: Instant,
    /// Header + payload, as received.
    pub data: [u8; 258],
    /// Valid bytes in `data`, the 2-byte header included.
    pub len: u16,
    /// Connection event this was captured in, counted from the start of the
    /// follow rather than as the link layer's wrapping 16-bit counter.
    pub ev: u32,
    /// Position in the capture, assigned at capture time so the queue cannot
    /// renumber packets.
    pub pkt_no: u32,
    pub dir: &'static str,
    pub crc_ok: bool,
    /// The link was encrypted when this PDU aired. Its payload is ciphertext, so
    /// [`emit_pdu`] dumps the bytes without decoding them.
    pub encrypted: bool,
}

pub static RX_QUEUE: Channel<CriticalSectionRawMutex, RxPdu, RX_QUEUE_DEPTH> = Channel::new();

/// PDUs captured but never decoded because the queue was full. Reported on the
/// `FOLLOW end` line: `Packet[N]` numbers are assigned at capture, so a gap in
/// the printed sequence is explained by this counter rather than by a lost
/// packet on air.
static DROPPED: AtomicU32 = AtomicU32::new(0);

/// Per-connection encryption tracking threaded through [`capture`].
#[derive(Default)]
struct EncState {
    /// True once the link's payloads are ciphertext; from here decode and control
    /// action both stop, and every queued PDU is flagged for a raw ciphertext dump.
    on: bool,
    /// Event LL_ENC_REQ was seen, if any — arms the grace fallback in [`capture`]
    /// for when the confirming LL_ENC_RSP/START_ENC PDUs are all missed.
    req_ev: Option<u32>,
}

/// Queue one captured PDU for decoding and return the action the follow loop has
/// to apply before the next event.
///
/// The two jobs are split at exactly this point because they have different
/// deadlines: the timeline updates in an LL Control PDU must be applied before
/// the instant they name, while the readable rendering of the same bytes can
/// happen whenever the decoder gets there. Empty PDUs — the keepalives that make
/// up most of an idle link — are neither queued nor numbered; the closing
/// `empty=` count accounts for them.
fn capture(
    dir: &'static str,
    ev: u32,
    crc_ok: bool,
    t_air: Instant,
    buf: *mut [u8; 258],
    pkt_no: &mut u32,
    enc: &mut EncState,
) -> ControlAction {
    let b = unsafe { &*buf };
    let hdr = ll::Header::parse(b);
    if hdr.len == 0 {
        return ControlAction::None;
    }
    let end = (2 + hdr.len).min(b.len());

    // Direction by true origin, not capture slot. The peripheral reply is caught in
    // the slave slot, but so is a master *continuation* when the reply is missed and
    // the master's next PDU lands inside the reply window. `CONNECTION_UPDATE_IND`
    // (0x00) and `CHANNEL_MAP_IND` (0x01) are central-only, so one showing up in the
    // slave slot is that case — label it C->P by what it is, not where it landed.
    let dir = if dir == DIR_P2C && crc_ok && hdr.llid == 0b11 && matches!(b.get(2), Some(0x00 | 0x01))
    {
        DIR_C2P
    } else {
        dir
    };

    // Grace fallback: if the LL_ENC_RSP/START_ENC that normally latches `enc.on`
    // was missed, the LL_ENC_REQ we did see still tells us encryption is imminent.
    // The whole start-up handshake completes within a couple of connection events,
    // so once `ENC_GRACE_EVENTS` have passed since LL_ENC_REQ, everything on air is
    // ciphertext — mark it so rather than mis-parsing it as LL/L2CAP.
    const ENC_GRACE_EVENTS: u32 = 2;
    if !enc.on
        && let Some(req) = enc.req_ev
        && ev >= req + ENC_GRACE_EVENTS
    {
        enc.on = true;
    }

    *pkt_no += 1;
    let mut p = RxPdu {
        t_air,
        data: [0u8; 258],
        len: end as u16,
        ev,
        pkt_no: *pkt_no,
        dir,
        crc_ok,
        encrypted: enc.on,
    };
    p.data[..end].copy_from_slice(&b[..end]);
    if RX_QUEUE.try_send(p).is_err() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }

    // Once the link is encrypted the payload — opcode included — is ciphertext, so
    // it can be neither decoded nor acted on: a ciphertext byte that happens to be
    // 0x02 must not be read as an LL_TERMINATE_IND.
    if enc.on {
        return ControlAction::None;
    }

    // A CRC failure means the bytes are unreliable, so they are queued for the
    // dump but never acted on.
    if crc_ok && hdr.llid == 0b11 {
        let action = control_action(&b[2..end]);
        // LL_ENC_RSP is the peripheral's agreement to start encryption and the
        // last plaintext control PDU; every data PDU from the next one on is
        // ciphertext. LL_START_ENC_REQ/RSP (0x05/0x06) come next and confirm the
        // same thing, so latching on any of the three catches the boundary even
        // when one of them is missed. LL_ENC_REQ (0x03) does not latch here — the
        // 0x04 reply that follows it still carries a plaintext SKD/IV worth
        // decoding — but it arms the grace fallback above for when 0x04..=0x06 are
        // all missed (as they were in the capture this handles).
        match b[2] {
            0x03 => enc.req_ev = Some(ev),
            0x04..=0x06 => enc.on = true,
            _ => {}
        }
        action
    } else {
        ControlAction::None
    }
}

/// Drains [`RX_QUEUE`], decoding and logging one PDU at a time.
///
/// Runs between connection events, so the decode overlaps the receive windows
/// the follow loop is waiting on.
#[embassy_executor::task]
pub async fn log_task() -> ! {
    loop {
        let p = RX_QUEUE.receive().await;
        crate::with_log_stamp(p.t_air, || emit_pdu(&p));
    }
}

/// Wait for the decode task to catch up, so the closing `FOLLOW end` line lands
/// after the packets it counts. Bounded: a queue that is not draining must not
/// hold the follower off the advertising scan.
async fn drain_queue() {
    let deadline = Instant::now() + Duration::from_millis(50);
    while !RX_QUEUE.is_empty() && Instant::now() < deadline {
        Timer::after_micros(500).await;
    }
}

// ── Decoding ──────────────────────────────────────────────────────────────────

/// Decode one captured PDU: the header line with its sequence flags, then the
/// Link Layer control parameters or the L2CAP frame and whichever protocol owns
/// its CID, then the hex dump.
fn emit_pdu(p: &RxPdu) {
    let b = &p.data[..p.len as usize];
    let hdr = ll::Header::parse(b);
    let payload = &b[2..];

    // `ev` rides on every packet line as well as on the event summary: a packet
    // number alone cannot be tied back to a channel, anchor or miss streak, and
    // that correlation is what a capture is read for. The sequence flags follow
    // it, so a stalled `sn` — the signature of a retransmission — is visible
    // without comparing payloads.
    let mut head = crate::LogLine::new();
    let _ = write!(head, "    Packet[{}] EV{} {} ", p.pkt_no, p.ev, p.dir);
    hdr.write_flags(&mut head);

    if !p.crc_ok {
        ulogf!("{} CRC-ERR llid={} len={} (not decoded)\r\n", head, hdr.llid, hdr.len);
        crate::hexdump(payload, 0, 6);
        return;
    }

    // Ciphertext: the header (LLID, length, sequence flags) is in the clear and
    // still worth its line, but the payload is meaningless until decrypted, so
    // decoding it would only manufacture bogus LL/L2CAP fields.
    if p.encrypted {
        // The bytes are the whole record of the link from here on, and offline
        // decryption needs them, so they are dumped even though nothing on the
        // probe can read them. Dense: 128 to a line, which holds the 251-byte
        // PDUs a Data Length Update negotiates to two lines. `ct` marks them as
        // ciphertext + a trailing 4-byte MIC, not a decodable payload.
        ulogf!("{} encrypted llid={} len={} (ciphertext)\r\n", head, hdr.llid, hdr.len);
        crate::hexdump_dense("ct", payload, 6);
        return;
    }

    // A layer that recognises the payload prints its fields; only bytes no layer
    // decoded are dumped, so a fully decoded packet carries no redundant hex.
    match hdr.llid {
        0b11 => {
            ulogf!(
                "{} LL_CTRL {} (0x{:02X}) len={}\r\n",
                head, ll::ctrl_name(payload[0]), payload[0], hdr.len
            );
            if !ll::emit_ctrl_params(payload) {
                crate::hexdump(payload, 0, 6);
            }
        }
        0b10 => {
            if !l2cap::emit(&head, payload) {
                crate::hexdump(payload, 0, 6);
            }
        }
        0b01 => {
            // Continuation fragment of an L2CAP frame started in an earlier
            // event. We don't reassemble, so there is no header to decode.
            ulogf!("{} L2CAP continuation len={}\r\n", head, hdr.len);
            crate::hexdump(payload, 0, 6);
        }
        _ => {
            ulogf!("{} RFU llid=0 len={}\r\n", head, hdr.len);
            crate::hexdump(payload, 0, 6);
        }
    }
}

// ── LL control actions ────────────────────────────────────────────────────────

enum ControlAction {
    None,
    Terminate,
    Update(PendUpd),
    Map(PendMap),
    Phy(PendPhy),
}

/// Read an LL Control PDU payload (`opcode` + parameters) for what the follower
/// must do about it. The parameters themselves are printed by [`emit_pdu`] off
/// the decode queue; the two lines emitted here are about following, not about
/// the PDU, and are rare enough to belong on the capture path where the decision
/// is made.
fn control_action(d: &[u8]) -> ControlAction {
    match d[0] {
        0x00 if d.len() >= 12 => {
            // LL_CONNECTION_UPDATE_IND: WinSize WinOffset Interval Latency Timeout Instant.
            ControlAction::Update(PendUpd {
                win_size: d[1],
                win_offset: u16::from_le_bytes([d[2], d[3]]),
                interval: u16::from_le_bytes([d[4], d[5]]),
                latency: u16::from_le_bytes([d[6], d[7]]),
                timeout: u16::from_le_bytes([d[8], d[9]]),
                instant: u16::from_le_bytes([d[10], d[11]]),
            })
        }
        0x01 if d.len() >= 8 => {
            // LL_CHANNEL_MAP_IND: ChM(5) Instant(2).
            ControlAction::Map(PendMap {
                chm: [d[1], d[2], d[3], d[4], d[5]],
                instant: u16::from_le_bytes([d[6], d[7]]),
            })
        }
        0x02 => ControlAction::Terminate,
        // 0x03 (LL_ENC_REQ) only opens the handshake — the 0x04 reply to it is
        // still plaintext and carries the peripheral's SKD/IV. `capture` latches
        // `encrypted` on 0x04..=0x06 for that reason, so the two must agree
        // about where the boundary is.
        0x03 => {
            ulogf!("      LL_ENC_REQ — encryption starting, payloads still plaintext\r\n");
            ControlAction::None
        }
        0x04..=0x06 => {
            ulogf!("      {} — payloads now encrypted\r\n", ll::ctrl_name(d[0]));
            ControlAction::None
        }
        // 0x18, not 0x16: 0x16 is LL_PHY_REQ (a negotiation that may come to
        // nothing), while LL_PHY_UPDATE_IND is what actually switches the PHY at
        // its instant. Both fields zero means the negotiation settled on no
        // change, and then the instant carries nothing to act on.
        0x18 if d.len() >= 5 => {
            let (c_to_p, p_to_c) = (d[1], d[2]);
            if c_to_p == 0 && p_to_c == 0 {
                return ControlAction::None;
            }
            ControlAction::Phy(PendPhy {
                c_to_p,
                p_to_c,
                instant: u16::from_le_bytes([d[3], d[4]]),
            })
        }
        _ => ControlAction::None,
    }
}

// ── Mode ──────────────────────────────────────────────────────────────────────
//
// The conn-follow boot mode. The RGB LED is driven **inline per radio event**
// (blue advert / green master / red slave) from inside [`run`], so the mode holds a
// [`Gpio`] and `led_control` is a no-op; the decode/PCAP consumer is the separate
// [`log_task`] draining [`RX_QUEUE`].

/// Holds the [`Gpio`] LED it toggles between radio events; `K` names the sink type
/// for trait uniformity (unused — the consumer is a separate task).
pub struct ConnFollow<K: super::CaptureSink> {
    leds: Option<Gpio>,
    _k: PhantomData<K>,
}

impl<K: super::CaptureSink> ConnFollow<K> {
    pub fn new(leds: Gpio) -> Self {
        Self { leds: Some(leds), _k: PhantomData }
    }
}

impl<K: super::CaptureSink> Mode for ConnFollow<K> {
    type Sink = K;

    async fn init<F: core::future::Future<Output = ()>>(&mut self, _ctx: &'static Ctx<K>, setup: F) {
        setup.await;
    }

    async fn run(&mut self, _ctx: &'static Ctx<K>) -> ! {
        let leds = self.leds.take().expect("run once");
        run(leds).await;
        unreachable!()
    }

    async fn led_control<L: OnBoardLed>(_led: &mut L) -> ! {
        // The LED is driven inline in `run`, per radio event — nothing separate.
        pending().await
    }
}
