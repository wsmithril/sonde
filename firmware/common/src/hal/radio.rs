//! RADIO peripheral: shared config and control.
//!
//! Every mode drives the single nRF52840 RADIO — the BLE sniffer, the GATT
//! central, the RSSI sweep and the 802.15.4 sniffer — so the low-level
//! access-address / CRC constants, the disable guard, the hardware-scheduled RXEN,
//! the packet-layout setup and the per-standard configuration live here rather than
//! being duplicated per mode.

use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;

// ── BLE advertising constants ─────────────────────────────────────────────────

/// The fixed BLE advertising access address (little-endian on air).
pub const ADV_AA: u32 = 0x8E89_BED6;
/// Advertising-channel CRC init value (24-bit).
pub const ADV_CRC_INIT: u32 = 0x55_5555;
/// BLE CRC polynomial (x24 + x10 + x9 + x6 + x4 + x3 + x + 1), shared by adv and
/// data channels; only the init value differs per connection.
pub const ADV_CRC_POLY: u32 = 0x00_065B;

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
// unused (embassy-time runs on RTC1) and PPI channel 0 is free — the RADIO is
// driven here through raw registers, not the embassy Ppi HAL.

/// PPI channel routing TIMER1.EVENTS_COMPARE[0] → RADIO.TASKS_RXEN.
const PPI_CH_RXEN: usize = 0;

/// Leads at or below this fire RXEN immediately: the timer path's own setup
/// latency would otherwise land after so near a deadline, and the short-offset
/// case already performed best when driven directly.
const RXEN_MIN_LEAD_US: u32 = 20;

/// Arm `RADIO.TASKS_RXEN` to fire `delay_us` from now, in hardware.
///
/// Programs a one-shot TIMER1 compare and routes it to TASKS_RXEN over a PPI
/// channel, so the receiver ramps at the scheduled instant even while another
/// task holds the CPU. COMPARE0 also stops the timer through a built-in
/// shortcut, so the arm is self-terminating. Pair with [`disarm_rxen`] once the
/// RX window closes. Very short leads fire immediately — see [`RXEN_MIN_LEAD_US`].
pub fn arm_rxen_after(delay_us: u32) {
    let r = pac::RADIO;
    if delay_us <= RXEN_MIN_LEAD_US {
        r.tasks_rxen().write_value(1);
        return;
    }
    let t = pac::TIMER1;
    t.tasks_stop().write_value(1);
    t.tasks_clear().write_value(1);
    t.mode().write(|w| w.set_mode(pac::timer::vals::Mode::Timer));
    t.bitmode().write(|w| w.set_bitmode(pac::timer::vals::Bitmode::_32bit));
    t.prescaler().write(|w| w.set_prescaler(4)); // 16 MHz >> 4 = 1 MHz → 1 tick = 1 µs
    t.cc(0).write_value(delay_us);
    t.events_compare(0).write_value(0);
    t.shorts().write(|w| w.set_compare_stop(0, true));

    let ppi = pac::PPI;
    ppi.ch(PPI_CH_RXEN)
        .eep()
        .write_value(t.events_compare(0).as_ptr() as usize as u32);
    ppi.ch(PPI_CH_RXEN)
        .tep()
        .write_value(r.tasks_rxen().as_ptr() as usize as u32);
    ppi.chenset().write(|w| w.set_ch(PPI_CH_RXEN, true));

    t.tasks_start().write_value(1);
}

/// Tear down the [`arm_rxen_after`] wiring: disable the PPI channel and stop
/// TIMER1. Safe whether or not the compare fired — the one-shot shortcut may
/// already have stopped the timer, and stopping a stopped timer is a no-op.
pub fn disarm_rxen() {
    pac::PPI.chenclr().write(|w| w.set_ch(PPI_CH_RXEN, true));
    pac::TIMER1.tasks_stop().write_value(1);
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
    let r = pac::RADIO;
    r.mode().write(|w| w.set_mode(vals::Mode::Ble1mbit));
    set_pcnf0(vals::Plen::_8bit);
    r.pcnf1().write(|w| {
        // maxlen is only a cap; 255 lets large AUX_ADV_IND payloads pass CRC
        // during aux following without truncation, and is harmless for the
        // small legacy PDUs seen on the primary channels.
        w.set_maxlen(255);
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
    r.mode().write(|w| w.set_mode(vals::Mode::Ieee802154250kbit));
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
