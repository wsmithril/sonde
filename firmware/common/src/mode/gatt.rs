//! Active GATT enumeration — BLE central role.
//!
//! Unlike the passive sniffer ([`crate::mode::ble_sniff`]), this mode *transmits*: it
//! surveys connectable advertisers, opens a connection to the strongest one not
//! seen in the last hour, walks its attribute database (services →
//! characteristics → descriptors), reads each readable characteristic value,
//! prints the table over USB serial, tears the connection down, and repeats.
//!
//! All GATT/ATT decoding lives in this module (the shared `decoder` handles only
//! advertising payloads). Radio primitives shared with the sniffer come from
//! [`crate::hal`].
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
//! [`crate::mode::ble_sniff::follow_aux`]); within an event we busy-poll the sub-ms
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

use core::marker::PhantomData;

use embassy_time::{Duration, Instant, Timer};

use super::{Ctx, Mode, drive_indicator};
use crate::central::*;
use crate::hal::radio::{configure_ble, ensure_disabled};
use crate::led::{OnBoardLed, Pwm};
use crate::{Rng, led};

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
        ensure_disabled();
        configure_ble();
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
        ensure_disabled();
        configure_ble();
        return;
    }

    // Switch the radio off the advertising AA/CRC (used to send the CONNECT_IND)
    // onto this connection's access address + CRC init before the first event.
    // Without this the master data PDUs go out on the advertising AA (0x8E89BED6)
    // and the peer — listening on the connection AA — never decodes them, so it never replies.
    configure_conn_radio();

    // Generic enumeration only walks the GATT table; this mode has no device
    // protocol, so it picks no handles out of the walk.
    let services = enumerate(&mut conn, |_vh, _uuid| {}).await;

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
        ensure_disabled();
        configure_ble();
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

// ── Mode ──────────────────────────────────────────────────────────────────────
//
// The GATT-enum boot mode: an active central that surveys connectable advertisers,
// connects to the strongest one not seen recently, walks its GATT table, then
// disconnects and repeats — the [`run`] loop above. Output is text straight to the
// log, so it uses neither `sink_frame` nor the sink; its LED is the state-colour
// [`drive_indicator`], signalled from inside [`run`].

/// ZST carrier of the sink type `K`; GATT holds no state.
pub struct GattEnum<K: super::CaptureSink>(PhantomData<K>);

impl<K: super::CaptureSink> GattEnum<K> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<K: super::CaptureSink> Default for GattEnum<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: super::CaptureSink> Mode for GattEnum<K> {
    type Sink = K;

    async fn init<F: core::future::Future<Output = ()>>(&mut self, _ctx: &'static Ctx<K>, setup: F) {
        setup.await;
    }

    async fn run(&mut self, ctx: &'static Ctx<K>) -> ! {
        loop {
            run(ctx.rng()).await;
        }
    }

    async fn led_control<L: OnBoardLed>(led: &mut L) -> ! {
        drive_indicator(led).await
    }
}

/// Spawnable LED task — the state-colour indicator (`crate::led::LED` signal).
/// Shared with the Midea mode.
#[embassy_executor::task]
pub async fn led_task(mut leds: Pwm) -> ! {
    drive_indicator(&mut leds).await
}
