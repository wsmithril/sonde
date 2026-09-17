//! RADIO peripheral: shared config and control.
//!
//! Every mode drives the single nRF52840 RADIO — the BLE sniffer, the GATT
//! central, the RSSI sweep and the 802.15.4 sniffer — so the low-level
//! access-address / CRC constants, the disable guard, the hardware-scheduled RXEN,
//! the packet-layout setup and the per-standard configuration live here rather than
//! being duplicated per mode.

use core::sync::atomic::{AtomicBool, Ordering};
use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;
use embassy_time::{Duration, Instant};

// ── BLE advertising constants ─────────────────────────────────────────────────

/// The fixed BLE advertising access address (little-endian on air).
pub const ADV_AA: u32 = 0x8E89_BED6;
/// Advertising-channel CRC init value (24-bit).
pub const ADV_CRC_INIT: u32 = 0x55_5555;
/// BLE CRC polynomial (x24 + x10 + x9 + x6 + x4 + x3 + x + 1), shared by adv and
/// data channels; only the init value differs per connection.
pub const ADV_CRC_POLY: u32 = 0x00_065B;

// ── Bounded BLE CRC repair ───────────────────────────────────────────────────

/// The bit order in which this RADIO exposes the received CRC.
///
/// The PDU shift-register state is not documented in the same representation as
/// `RXCRC`.  We learn this from a packet the hardware has already CRC-validated
/// instead of relying on a chip-specific assumption.
#[derive(Copy, Clone)]
enum RxCrcOrder {
    State,
    BitReversed24,
}

/// Per-radio calibration for optional, bounded CRC-error repair.
///
/// A repair is admitted only when a clean PDU has first established how RXCRC is
/// represented.  It changes payload bits only: a damaged length header would
/// make the DMA extent unknowable, so accepting it would turn a useful recovery
/// path into a parser-safety risk.
#[derive(Default)]
pub struct BleCrcRepair {
    order: Option<RxCrcOrder>,
}

impl BleCrcRepair {
    /// Record a CRC-good PDU and calibrate `RXCRC`'s representation if possible.
    pub fn observe_good(&mut self, pdu: &[u8], init: u32, rxcrc: u32) {
        if self.order.is_some() {
            return;
        }
        let state = ble_crc_state(pdu, init);
        self.order = if rxcrc == state {
            Some(RxCrcOrder::State)
        } else if rxcrc == reverse24(state) {
            Some(RxCrcOrder::BitReversed24)
        } else {
            None
        };
    }

    /// Correct one damaged payload bit, returning its PDU bit index.
    ///
    /// This is O(PDU bits): at most 2,064 short state updates for a 258-byte
    /// DMA buffer.  Two-bit and three-bit brute force would be O(n²) and O(n³),
    /// respectively, and are intentionally not attempted on the capture path.
    pub fn repair_one_payload_bit(&self, pdu: &mut [u8], init: u32, rxcrc: u32) -> Option<u16> {
        self.repair_one_payload_bit_until(pdu, init, rxcrc, || false)
    }

    /// Correct one damaged payload bit unless `expired` says a newer packet has
    /// arrived. `expired` is polled every 64 candidate bits, bounding sniffer
    /// work to the space between packet arrivals as well as to one PDU.
    pub fn repair_one_payload_bit_until<F>(
        &self,
        pdu: &mut [u8],
        init: u32,
        rxcrc: u32,
        expired: F,
    ) -> Option<u16>
    where
        F: FnMut() -> bool,
    {
        let expected_state = match self.order? {
            RxCrcOrder::State => rxcrc,
            RxCrcOrder::BitReversed24 => reverse24(rxcrc),
        };
        repair_one_bit_from(16, pdu, init, expected_state, expired)
    }
}

/// CRC state representation used by BLE's link-layer shift register. PDU bits
/// are fed least-significant-bit first.
fn ble_crc_state(pdu: &[u8], init: u32) -> u32 {
    let mut state = init & 0x00FF_FFFF;
    for &byte in pdu {
        for bit in 0..8 {
            let feedback = ((state >> 23) ^ u32::from(byte >> bit)) & 1;
            state = (state << 1) & 0x00FF_FFFF;
            if feedback != 0 {
                state ^= ADV_CRC_POLY;
            }
        }
    }
    state
}

fn reverse24(v: u32) -> u32 {
    v.reverse_bits() >> 8
}

/// Repair one bit at or after `first_bit`, using the received CRC syndrome.
fn repair_one_bit_from(
    first_bit: usize,
    pdu: &mut [u8],
    init: u32,
    expected_state: u32,
    mut expired: impl FnMut() -> bool,
) -> Option<u16> {
    let syndrome = ble_crc_state(pdu, init) ^ expected_state;
    if syndrome == 0 || pdu.len() > u16::MAX as usize / 8 {
        return None;
    }

    // A flipped final input bit changes the state by this value. Walking toward
    // the start applies the zero-input transition once per preceding bit.
    let mut delta = ADV_CRC_POLY;
    for bit_index in (0..pdu.len() * 8).rev() {
        if bit_index.is_multiple_of(64) && expired() {
            return None;
        }
        if bit_index >= first_bit && delta == syndrome {
            pdu[bit_index / 8] ^= 1 << (bit_index % 8);
            return Some(bit_index as u16);
        }
        let feedback = (delta >> 23) & 1;
        delta = (delta << 1) & 0x00FF_FFFF;
        if feedback != 0 {
            delta ^= ADV_CRC_POLY;
        }
    }
    None
}

#[cfg(test)]
mod crc_tests {
    use super::*;

    #[test]
    fn crc24_ble_check_value() {
        // Published CRC-24/BLE check value, in the conventional on-air bit order.
        assert_eq!(
            reverse24(ble_crc_state(b"123456789", ADV_CRC_INIT)),
            0xC2_5A_56
        );
    }

    #[test]
    fn repairs_one_payload_bit() {
        let init = 0x12_3456;
        let original = [
            0x02, 0x0A, 0x19, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let expected = ble_crc_state(&original, init);
        let mut bad = original;
        bad[7] ^= 0b0010_0000;
        assert_eq!(
            repair_one_bit_from(16, &mut bad, init, expected, || false),
            Some(61)
        );
        assert_eq!(bad, original);
    }
}

// ── Radio helpers ─────────────────────────────────────────────────────────────

/// Spin until the RADIO reports DISABLED, then consume the event. `false` means
/// it never got there within the bound.
///
/// The bound is the point. On a single-priority cooperative executor an
/// unbounded `while events_disabled == 0 {}` is not a stall, it is the end of
/// the program: the scan task never yields again, so the USB drain task never
/// runs and the capture stops mid-line with no diagnostic to say why. Bounding
/// it turns that silence into a log line and a recovery.
///
/// 100_000 volatile reads is roughly 15 ms at 64 MHz, against a ramp-down the
/// datasheet caps at ~6 µs — three orders of magnitude of headroom, so the bound
/// cannot trip on a radio that is merely slow.
#[must_use]
pub fn wait_disabled() -> bool {
    let r = pac::RADIO;
    for _ in 0..100_000u32 {
        if r.events_disabled().read() != 0 {
            r.events_disabled().write_value(0);
            return true;
        }
    }
    false
}

/// Drive the RADIO to DISABLED and wait for it, recovering if it will not go.
///
/// SHORTS are cleared first. With `disabled_txen`/`disabled_rxen` armed the
/// radio re-triggers itself the instant it reaches DISABLED and never settles;
/// with `end_start` armed — which the primary scan leaves set — an END landing
/// during the ramp-down re-arms the receiver underneath the disable.
///
/// EVENTS_DISABLED is cleared *before* TASKS_DISABLE is triggered. The other
/// order loses the event whenever the radio reaches DISABLED between the two
/// register writes, and then there is nothing left for the wait to observe.
///
/// A timeout only logs. The caller then reconfigures and starts as usual: if the
/// radio really is wedged that operation returns nothing and the next one tries
/// again, which beats freezing — and `radio_disable_timeout` in the capture is
/// the evidence that would say so. Power-cycling instead would reset MODE, PCNF,
/// the access address, CRC and TIFS, none of which the per-operation setup
/// rewrites, so the escape from a hypothetical hang would be certain deafness.
fn force_disable() {
    let r = pac::RADIO;
    r.shorts().write(|_w| {});
    r.events_disabled().write_value(0);
    r.tasks_disable().write_value(1);
    if !wait_disabled() {
        ulog!("radio_disable_timeout\r\n");
    }
}

/// Ensures the RADIO is in the DISABLED state before we issue any task. If it is
/// still running from a previous operation, disable it and say so — a radio left
/// running where the caller expected DISABLED is a bug worth seeing.
///
/// Use [`disable_silent`] instead where a running radio is the normal
/// case, or the log fills with reports of the expected.
pub fn ensure_disabled() {
    if pac::RADIO.state().read().0 != 0 {
        ulog!("radio_stuck\r\n");
        crate::RADIO_RECOVERED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        force_disable();
    }
}

/// Force the RADIO to DISABLED, silently. Use where the radio is expected to
/// still be running — tearing down an armed RX or a turnaround chain — as
/// opposed to [`ensure_disabled`], which flags it. No-op if already
/// DISABLED, so it cannot wait on the event of a radio that will never move.
pub fn disable_silent() {
    if pac::RADIO.state().read().0 != 0 {
        force_disable();
    }
}

// ── Hardware-scheduled RXEN ─────────────────────────────────────────────────
//
// Opening the receiver at a precise future instant cannot go through the
// executor: `Timer::at(open_at).await` yields, the decode task runs for however
// long it runs, and TASKS_RXEN fires only when the scan task is next scheduled —
// late, and later the longer the decode queue. That is why aux hit rate fell off
// with the aux offset. TIMER1 plus one PPI channel take the executor out of the
// one deadline that matters: the compare event drives TASKS_RXEN in hardware at
// the programmed time regardless of what the CPU is doing. TIMER1 is otherwise
// unused (embassy-time runs on RTC1) and PPI channels 0–1 are free — the RADIO
// is driven here through raw registers, not the embassy Ppi HAL.

/// PPI channel routing TIMER1.EVENTS_COMPARE[0] → RADIO.TASKS_RXEN.
const PPI_CH_RXEN: usize = 0;
/// PPI channel routing RADIO.EVENTS_END → TIMER1.TASKS_CAPTURE[1].
const PPI_CH_END_CAPTURE: usize = 1;

/// A mapping from TIMER1's 1 MHz counter to Embassy time for one RX window.
///
/// `Instant::now()` is based on RTC1 and therefore quantized to its 32.768 kHz
/// tick. `RADIO.END` is captured into TIMER1 over PPI at the hardware event, so
/// deriving an end time through this mapping removes poll-loop latency from the
/// connection follower's re-anchor.
#[derive(Clone, Copy)]
pub struct RadioEndClock {
    instant: Instant,
    counter: u32,
}

static TIMER1_RUNNING: AtomicBool = AtomicBool::new(false);

impl RadioEndClock {
    /// Capture and return TIMER1's current 1 MHz tick count.
    pub fn now_ticks(&self) -> u32 {
        let t = pac::TIMER1;
        t.tasks_capture(2).write_value(1);
        t.cc(2).read()
    }

    /// Return the TIMER1 tick latched by the most recent `RADIO.END` event.
    ///
    /// Read this before another received PDU reaches END: CC1 deliberately
    /// holds only the latest capture.
    pub fn end_ticks(&self) -> u32 {
        pac::TIMER1.cc(1).read()
    }

    /// Convert a TIMER1 tick to an `Instant` for log timestamps only.
    ///
    /// Connection timing must retain the tick value: `Instant` is RTC1-based
    /// and rounds to 30.5 µs ticks.
    pub fn instant_at(&self, ticks: u32) -> Instant {
        self.instant + Duration::from_micros(ticks.wrapping_sub(self.counter) as u64)
    }

    /// Return the time captured by the most recent `RADIO.END` event.
    ///
    /// This compatibility helper is for log timestamps. Connection anchors use
    /// [`Self::end_ticks`] directly so they retain TIMER1 precision.
    pub fn end_instant(&self) -> Instant {
        self.instant_at(self.end_ticks())
    }

    /// Hardware-arm RXEN at an absolute TIMER1 tick.
    ///
    /// The timer runs continuously for a connection follow. A signed modular
    /// comparison is safe here because no arm is more than one connection
    /// interval (< 2³¹ µs) away, including across TIMER1's 71-minute wrap.
    pub fn arm_rxen_at(&self, at: u32) {
        self.arm_task_at(at, pac::RADIO.tasks_rxen().as_ptr() as usize as u32);
    }

    /// Hardware-arm RADIO.TASKS_TXEN at an absolute TIMER1 tick.
    ///
    /// The central uses this to start its default-ramp TX early enough that the
    /// first bit lands on a 1 MHz connection anchor rather than an RTC-rounded
    /// approximation of one.
    pub fn arm_txen_at(&self, at: u32) {
        self.arm_task_at(at, pac::RADIO.tasks_txen().as_ptr() as usize as u32);
    }

    fn arm_task_at(&self, at: u32, task: u32) {
        let r = pac::RADIO;
        let now = self.now_ticks();
        let remaining = at.wrapping_sub(now) as i32;
        if remaining <= RXEN_MIN_LEAD_US as i32 {
            // The only current immediate caller is RXEN. TXEN is always armed
            // a full default-ramp before its air-time anchor.
            if task == r.tasks_txen().as_ptr() as usize as u32 {
                r.tasks_txen().write_value(1);
            } else {
                r.tasks_rxen().write_value(1);
            }
            return;
        }

        let t = pac::TIMER1;
        t.cc(0).write_value(at);
        t.events_compare(0).write_value(0);

        let ppi = pac::PPI;
        ppi.ch(PPI_CH_RXEN)
            .eep()
            .write_value(t.events_compare(0).as_ptr() as usize as u32);
        ppi.ch(PPI_CH_RXEN).tep().write_value(task);
        ppi.chenset().write(|w| w.set_ch(PPI_CH_RXEN, true));
    }
}

/// Leads at or below this fire RXEN immediately: the timer path's own setup
/// latency would otherwise land after so near a deadline, and the short-offset
/// case already performed best when driven directly.
const RXEN_MIN_LEAD_US: u32 = 20;

/// Start TIMER1's 1 MHz counter and capture every `RADIO.END` into CC1, or
/// reuse the running counter when another connection already owns the
/// connection timeline.
///
/// The returned clock maps the hardware counter to Embassy time. It remains
/// valid until [`disarm_rxen`] is called. TIMER1 intentionally keeps running
/// after COMPARE0 so it can timestamp the received packet.
pub fn start_end_capture() -> RadioEndClock {
    let r = pac::RADIO;
    let t = pac::TIMER1;
    if !TIMER1_RUNNING.swap(true, Ordering::AcqRel) {
        t.tasks_stop().write_value(1);
        t.tasks_clear().write_value(1);
        t.mode()
            .write(|w| w.set_mode(pac::timer::vals::Mode::Timer));
        t.bitmode()
            .write(|w| w.set_bitmode(pac::timer::vals::Bitmode::_32bit));
        t.prescaler().write(|w| w.set_prescaler(4)); // 16 MHz >> 4 = 1 MHz
        t.shorts().write(|_w| {});
        t.tasks_start().write_value(1);

        let ppi = pac::PPI;
        ppi.ch(PPI_CH_END_CAPTURE)
            .eep()
            .write_value(r.events_end().as_ptr() as usize as u32);
        ppi.ch(PPI_CH_END_CAPTURE)
            .tep()
            .write_value(t.tasks_capture(1).as_ptr() as usize as u32);
        ppi.chenset().write(|w| w.set_ch(PPI_CH_END_CAPTURE, true));
    }

    // Sample both clocks as closely as possible. The absolute phase may be off
    // by one RTC tick, but every later RADIO.END has TIMER1 precision.
    t.tasks_capture(2).write_value(1);
    RadioEndClock {
        instant: Instant::now(),
        counter: t.cc(2).read(),
    }
}

/// Arm `RADIO.TASKS_RXEN` to fire `delay_us` from now, in hardware, and return
/// a hardware END timestamp clock for this receive window.
///
/// TIMER1 COMPARE0 routes to TASKS_RXEN over PPI, so the receiver ramps at the
/// scheduled instant even while another task holds the CPU. Pair with
/// [`disarm_rxen`] once the RX window closes. Very short leads fire immediately
/// — see [`RXEN_MIN_LEAD_US`].
pub fn arm_rxen_after(delay_us: u32) -> RadioEndClock {
    let clock = start_end_capture();
    clock.arm_rxen_at(clock.now_ticks().wrapping_add(delay_us));
    clock
}

/// Tear down the RXEN and END-capture PPI wiring, then stop TIMER1.
pub fn disarm_rxen() {
    pac::PPI.chenclr().write(|w| {
        w.set_ch(PPI_CH_RXEN, true);
        w.set_ch(PPI_CH_END_CAPTURE, true);
    });
    pac::TIMER1.tasks_stop().write_value(1);
    TIMER1_RUNNING.store(false, Ordering::Release);
}

// ── Packet layout ─────────────────────────────────────────────────────────────

/// Writes `PCNF0` for a BLE uncoded packet: an 8-bit S0 (the PDU header's first
/// octet), an 8-bit LENGTH field, no S1, and the given preamble length (`_8bit`
/// for 1M, `_16bit` for 2M). Every reception/transmission in the firmware uses
/// this same header layout (advertising PDUs, aux PDUs and LL data PDUs all lead
/// with the 2-byte header).
pub fn set_pcnf0(plen: vals::Plen) {
    pac::RADIO.pcnf0().write(|w| {
        w.set_s0len(true);
        w.set_lflen(8);
        w.set_s1len(0);
        w.set_plen(plen);
    });
}

/// `PCNF0` for BLE Coded PHY (LE Long Range) reception: the same S0/LENGTH header
/// layout as [`set_pcnf0`], plus the 2-bit Coding Indicator (CILEN) and 3-bit
/// TERM1 (TERMLEN) that exist only on the coded PHY, and the LongRange preamble.
/// MODE must be `BleLr125kbit`; the radio auto-switches to S=2 for the payload
/// when the received CI field says so, so a single RX config covers both
/// S=8 (125 kbit) and S=2 (500 kbit) coded packets.
pub fn set_pcnf0_coded() {
    pac::RADIO.pcnf0().write(|w| {
        w.set_s0len(true);
        w.set_lflen(8);
        w.set_s1len(0);
        w.set_plen(vals::Plen::LongRange);
        w.set_cilen(2);
        w.set_termlen(3);
    });
}

/// Switch the RADIO to the fast (~40 µs) ramp-up. Safe only for RX-only modes: the
/// fast ramp has no fixed timing, so it cannot honour the T_IFS turnaround a central
/// needs — but the passive sniffers (BLE advert, 802.15.4) never reply, so they take
/// it to shave latency between re-arms. See the T_IFS note in [`arm_rxen_after`].
pub fn use_fast_ramp_up() {
    pac::RADIO.modecnf0().modify(|w| w.set_ru(vals::Ru::Fast));
}

/// Maps a BLE data-channel *index* (0..36, as carried in an AuxPtr or used when
/// hopping a connection) to the nRF FREQUENCY offset from 2400 MHz. Indices
/// 37/38/39 are the primary advertising channels and are not valid data
/// channels → `None`.
pub fn data_ch_freq(idx: u8) -> Option<u8> {
    match idx {
        0..=10 => Some(4 + 2 * idx),
        11..=36 => Some(6 + 2 * idx),
        _ => None,
    }
}

// ── BLE configuration ───────────────────────────────────────────────────────

/// Configures the RADIO for BLE 1M advertising-channel packet detection. The same
/// configuration is also used during RSSI-only scans: the AA matching and CRC
/// engines are idle when no packet reception is started (no TASKS_START), so they
/// do not interfere with RSSI measurements. Callers that need a data-channel AA
/// (a connection) overwrite BASE0/PREFIX0/CRCINIT afterwards.
pub fn configure_ble() {
    configure_ble_with_maxlen(255);
}

/// Configure BLE advertising reception with a caller-owned DMA payload limit.
/// The RADIO writes the S0 and LENGTH bytes in addition to this payload, so the
/// caller must reserve two more bytes in the PACKETPTR buffer.
pub fn configure_ble_with_maxlen(maxlen: u8) {
    let r = pac::RADIO;
    r.mode().write(|w| w.set_mode(vals::Mode::Ble1mbit));
    set_pcnf0(vals::Plen::_8bit);
    r.pcnf1().write(|w| {
        w.set_maxlen(maxlen);
        w.set_statlen(0);
        // BALEN=3: match the full 4-byte BLE access address. The low 3 bytes go
        // in BASE0 (left-justified), the top byte in PREFIX0.AP0.
        w.set_balen(3);
        w.set_endian(vals::Endian::Little);
        w.set_whiteen(true);
    });
    set_access_address(ADV_AA);
    r.rxaddresses().write(|w| w.set_addr0(true));
    r.crccnf().write(|w| {
        w.set_len(vals::Len::Three);
        w.set_skipaddr(vals::Skipaddr::Skip);
    });
    r.crcpoly().write(|w| w.set_crcpoly(ADV_CRC_POLY));
    r.crcinit().write(|w| w.set_crcinit(ADV_CRC_INIT));
    // Maximum TX power (+8 dBm). Boosts what we transmit — CONNECT_IND and
    // connection-event packets reach weaker/more distant peers, so more links form
    // and hold. It does NOT change the RSSI we *receive* (that is the peer's TX).
    // Passive sniffing never transmits, so this is harmless there. TXPOWER persists
    // across DISABLE, so setting it in the base config covers every mode.
    r.txpower().write(|w| w.set_txpower(vals::Txpower::Pos8dBm));
}

// ── IEEE 802.15.4 ─────────────────────────────────────────────────────────────

/// The 802.15.4 Start of Frame Delimiter. Where BLE syncs on a 4-byte access
/// address matched by the address engine, 802.15.4 syncs on this single byte
/// after four zero preamble octets — so BALEN is 0 here and there is no
/// per-network sync word to filter on. Every frame on the channel is offered to
/// us, and every burst of noise that happens to contain 0xA7 is too; the CRC is
/// the only filter, which is why the sniffer counts CRC failures rather than
/// treating them as anomalies.
const SFD_154: u8 = 0xA7;

/// 802.15.4 FCS: CRC-16-CCITT, x16 + x12 + x5 + 1, zero init.
const CRC_POLY_154: u32 = 0x0001_1021;

/// Configures the RADIO for IEEE 802.15.4 reception: O-QPSK DSSS, 250 kbit/s,
/// 2.4 GHz.
///
/// Register values follow the nRF52840 PS §6.20 802.15.4 setup (cross-checked
/// against `embassy_nrf::radio::ieee802154`, which this firmware does not use —
/// see the module docs on [`crate::mode::zigbee`] for why).
///
/// Differences from [`configure_ble`] worth naming, because they are the
/// ones that silently produce a deaf receiver if missed:
///   • `WHITEEN = false` — 802.15.4 has no data whitening. Leaving BLE's
///     whitener on decodes every byte to noise while CRC still occasionally
///     passes on short frames.
///   • `BALEN = 0` — no access-address match; SFD does the sync.
///   • `CRCINC = Include` — the PHR length field counts the 2-byte FCS, unlike
///     BLE's LENGTH which does not count its CRC.
///   • `PLEN = _32bitZero` — four 0x00 octets, not BLE's 0xAA/0x55 pattern.
///
/// The caller sets FREQUENCY per channel; see [`zb_ch_freq`].
pub fn configure_154() {
    let r = pac::RADIO;
    r.mode()
        .write(|w| w.set_mode(vals::Mode::Ieee802154250kbit));
    r.pcnf0().write(|w| {
        // PHR is one 8-bit length octet, and 802.15.4 has no S0/S1 equivalent.
        w.set_lflen(8);
        w.set_s0len(false);
        w.set_s1len(0);
        w.set_s1incl(vals::S1incl::Automatic);
        w.set_cilen(0);
        w.set_plen(vals::Plen::_32bitZero);
        w.set_crcinc(vals::Crcinc::Include);
    });
    r.pcnf1().write(|w| {
        // aMaxPHYPacketSize. Must stay <= the DMA buffer behind PACKETPTR:
        // MAXLEN is what bounds the write, not the PHR the air happens to carry.
        w.set_maxlen(127);
        w.set_statlen(0);
        w.set_balen(0);
        w.set_endian(vals::Endian::Little);
        w.set_whiteen(false);
    });
    r.sfd().write(|w| w.set_sfd(SFD_154));
    r.crccnf().write(|w| {
        w.set_len(vals::Len::Two);
        w.set_skipaddr(vals::Skipaddr::Ieee802154);
    });
    r.crcpoly().write(|w| w.set_crcpoly(CRC_POLY_154));
    r.crcinit().write(|w| w.set_crcinit(0));
}

/// Maps an 802.15.4 channel (11..=26) to the nRF FREQUENCY offset from 2400 MHz.
/// Channel 11 is 2405 MHz and they step 5 MHz, so the offset is `(ch - 10) * 5`.
pub fn zb_ch_freq(ch: u8) -> Option<u8> {
    match ch {
        11..=26 => Some((ch - 10) * 5),
        _ => None,
    }
}

/// Programs logical address 0 with a 4-byte access address. BASE0 holds the low
/// 3 bytes left-justified within the 32-bit register; PREFIX0.AP0 holds the top
/// byte. Used to switch between the fixed advertising AA and a per-connection AA.
pub fn set_access_address(aa: u32) {
    let r = pac::RADIO;
    r.base0().write_value((aa << 8) & 0xFFFF_FF00);
    r.prefix0().write(|w| w.set_ap0((aa >> 24) as u8));
}
