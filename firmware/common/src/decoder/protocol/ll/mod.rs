//! Link Layer: the data-channel PDU header and the LL Control PDUs.
//!
//! Core v5.4 Vol 6 Part B §2.4. Every packet on a data channel starts with a
//! 2-byte header — [`Header`] — whose LLID says whether the payload is an L2CAP
//! fragment or an LL Control PDU. Control PDUs are an opcode plus parameters;
//! [`emit_ctrl_params`] routes each opcode to the [`ctrl`] decoder that claims
//! it.
//!
//! Printing is separated from acting on purpose: a follower has to apply a
//! `CONNECTION_UPDATE_IND` or `CHANNEL_MAP_IND` at its instant, on the capture
//! path, while the readable rendering of the same bytes can happen later on
//! another task. This module only prints.

use core::fmt::Write;

pub mod ctrl;
mod features;

// ── PDU header ────────────────────────────────────────────────────────────────

/// Data-channel PDU header (Core v5.4 Vol 6 Part B §2.4, figure 2.12).
///
/// `sn`/`nesn` are the whole of the link's reliability protocol: a sender keeps
/// re-sending the same payload with the same `sn` until the peer's `nesn`
/// acknowledges it. Two captured packets with identical bytes are therefore
/// only a retransmission if `sn` also matches — otherwise they are two distinct
/// transmissions that happen to carry the same payload.
pub struct Header {
    /// 0b01 L2CAP continuation / empty, 0b10 L2CAP start, 0b11 LL Control.
    pub llid: u8,
    /// Next Expected Sequence Number: acknowledges the peer's `sn`.
    pub nesn: u8,
    /// Sequence Number of this transmission.
    pub sn: u8,
    /// More Data: the sender has more to send in this connection event.
    pub md: u8,
    /// CTE Present: a Constant Tone Extension follows the payload.
    pub cp: bool,
    /// Payload length in bytes, from the header's second octet.
    pub len: usize,
}

impl Header {
    /// Split the two header octets. `b` must be at least 2 bytes.
    pub fn parse(b: &[u8]) -> Header {
        Header {
            llid: b[0] & 0x03,
            nesn: (b[0] >> 2) & 1,
            sn: (b[0] >> 3) & 1,
            md: (b[0] >> 4) & 1,
            cp: b[0] & 0x20 != 0,
            len: b[1] as usize,
        }
    }

    /// Append `sn=… nesn=… md=…` (and `cp=1` when a CTE follows) to `s`.
    ///
    /// All three flags print on every packet, set or clear, so the columns line
    /// up down a capture and a stalled `sn` is visible by scanning rather than
    /// by comparing payloads. `cp` appears only when set, because it is rare and
    /// it changes how the trailing bytes should be read.
    pub fn write_flags(&self, s: &mut crate::LogLine) {
        let _ = write!(s, "sn={} nesn={} md={}", self.sn, self.nesn, self.md);
        if self.cp {
            let _ = s.push_str(" cp=1");
        }
    }
}

// ── Control PDUs ──────────────────────────────────────────────────────────────

/// Decode the parameters of an LL Control PDU and emit them as indented lines.
///
/// `p` is the control payload: opcode first, parameters after. The caller has
/// already printed the opcode name, so these lines carry only field values.
/// Returns whether an opcode decoder claimed the PDU: `false` for an opcode with
/// no registered decoder, so the caller can fall back to a hex dump of the bytes
/// rather than leaving them unrecorded.
pub fn emit_ctrl_params(p: &[u8]) -> bool {
    if p.is_empty() {
        return false;
    }
    match super::lookup(ctrl::CTRL, p[0]) {
        Some(d) => {
            d.decode(p);
            true
        }
        None => false,
    }
}

/// LL Control PDU opcode names (Core v5.4 Vol 6 Part B §2.4.2).
///
/// Covers every opcode, including the ones no [`ctrl`] decoder claims: naming a
/// PDU costs one table entry, and a capture that says `LL_PERIODIC_SYNC_IND`
/// over a hex dump is already most of what the reader needs.
pub fn ctrl_name(op: u8) -> &'static str {
    match op {
        0x00 => "LL_CONNECTION_UPDATE_IND",
        0x01 => "LL_CHANNEL_MAP_IND",
        0x02 => "LL_TERMINATE_IND",
        0x03 => "LL_ENC_REQ",
        0x04 => "LL_ENC_RSP",
        0x05 => "LL_START_ENC_REQ",
        0x06 => "LL_START_ENC_RSP",
        0x07 => "LL_UNKNOWN_RSP",
        0x08 => "LL_FEATURE_REQ",
        0x09 => "LL_FEATURE_RSP",
        0x0A => "LL_PAUSE_ENC_REQ",
        0x0B => "LL_PAUSE_ENC_RSP",
        0x0C => "LL_VERSION_IND",
        0x0D => "LL_REJECT_IND",
        0x0E => "LL_PERIPHERAL_FEATURE_REQ",
        0x0F => "LL_CONNECTION_PARAM_REQ",
        0x10 => "LL_CONNECTION_PARAM_RSP",
        0x11 => "LL_REJECT_EXT_IND",
        0x12 => "LL_PING_REQ",
        0x13 => "LL_PING_RSP",
        0x14 => "LL_LENGTH_REQ",
        0x15 => "LL_LENGTH_RSP",
        0x16 => "LL_PHY_REQ",
        0x17 => "LL_PHY_RSP",
        0x18 => "LL_PHY_UPDATE_IND",
        0x19 => "LL_MIN_USED_CHANNELS_IND",
        0x1A => "LL_CTE_REQ",
        0x1B => "LL_CTE_RSP",
        0x1C => "LL_PERIODIC_SYNC_IND",
        0x1D => "LL_CLOCK_ACCURACY_REQ",
        0x1E => "LL_CLOCK_ACCURACY_RSP",
        0x1F => "LL_CIS_REQ",
        0x20 => "LL_CIS_RSP",
        0x21 => "LL_CIS_IND",
        0x22 => "LL_CIS_TERMINATE_IND",
        0x23 => "LL_POWER_CONTROL_REQ",
        0x24 => "LL_POWER_CONTROL_RSP",
        0x25 => "LL_POWER_CHANGE_IND",
        0x26 => "LL_SUBRATE_REQ",
        0x27 => "LL_SUBRATE_IND",
        0x28 => "LL_CHANNEL_REPORTING_IND",
        0x29 => "LL_CHANNEL_STATUS_IND",
        0x2A => "LL_PERIODIC_SYNC_WR_IND",
        0x2B => "LL_FEATURE_EXT_REQ",
        0x2C => "LL_FEATURE_EXT_RSP",
        // BLE 6.0 Channel Sounding + Frame Space (names only; field decode of CS
        // PDUs is complex and rare — not worth it yet). Note the spec's out-of-order
        // security opcodes: 0x2D is CS_SEC_RSP, 0x39 is CS_SEC_REQ.
        0x2D => "LL_CS_SEC_RSP",
        0x2E => "LL_CS_CAPABILITIES_REQ",
        0x2F => "LL_CS_CAPABILITIES_RSP",
        0x30 => "LL_CS_CONFIG_REQ",
        0x31 => "LL_CS_CONFIG_RSP",
        0x32 => "LL_CS_REQ",
        0x33 => "LL_CS_RSP",
        0x34 => "LL_CS_IND",
        0x35 => "LL_CS_TERMINATE_REQ",
        0x36 => "LL_CS_FAE_REQ",
        0x37 => "LL_CS_FAE_RSP",
        0x38 => "LL_CS_CHANNEL_MAP_IND",
        0x39 => "LL_CS_SEC_REQ",
        0x3A => "LL_CS_TERMINATE_RSP",
        0x3B => "LL_FRAME_SPACE_REQ",
        0x3C => "LL_FRAME_SPACE_RSP",
        _ => "?",
    }
}

/// Controller error codes (Core v5.4 Vol 1 Part F), as carried by
/// `LL_TERMINATE_IND`, `LL_REJECT_IND`, `LL_REJECT_EXT_IND` and
/// `LL_CIS_TERMINATE_IND`.
///
/// The code is the difference between a link that ended and a link that failed:
/// `remote-user-terminated` is a peer closing normally, `conn-timeout` is one
/// that stopped answering, and `instant-passed` or `unsupported-ll-param-value`
/// point at the procedure that broke rather than at the radio.
pub fn error_name(code: u8) -> &'static str {
    match code {
        0x00 => "success",
        0x02 => "unknown-connection-id",
        0x04 => "page-timeout",
        0x05 => "auth-failure",
        0x06 => "pin-or-key-missing",
        0x07 => "memory-capacity-exceeded",
        0x08 => "conn-timeout",
        0x09 => "conn-limit-exceeded",
        0x0C => "command-disallowed",
        0x0D => "insufficient-resources",
        0x0E => "insufficient-security",
        0x11 => "unsupported-feature-or-param",
        0x12 => "invalid-parameters",
        0x13 => "remote-user-terminated",
        0x14 => "remote-low-resources",
        0x15 => "remote-power-off",
        0x16 => "local-host-terminated",
        0x1A => "unsupported-remote-feature",
        0x1E => "invalid-ll-parameters",
        0x1F => "unspecified",
        0x20 => "unsupported-ll-param-value",
        0x21 => "role-change-not-allowed",
        0x22 => "ll-response-timeout",
        0x23 => "ll-procedure-collision",
        0x25 => "encryption-mode-not-acceptable",
        0x28 => "instant-passed",
        0x29 => "unit-key-pairing-unsupported",
        0x2A => "different-transaction-collision",
        0x2F => "insufficient-security",
        0x30 => "parameter-out-of-mandatory-range",
        0x3B => "unacceptable-connection-parameters",
        0x3D => "terminated-mic-failure",
        0x3E => "connection-failed-to-be-established",
        0x40 => "coarse-clock-adjustment-rejected",
        0x42 => "unknown-advertising-identifier",
        0x43 => "limit-reached",
        0x44 => "operation-cancelled-by-host",
        0x45 => "packet-too-long",
        _ => "?",
    }
}

/// Append the PHYs named by a `TX_PHYS` / `RX_PHYS` / `PHYS` bitmask.
///
/// Shared by every procedure that names a PHY — the PHY update itself, minimum
/// used channels, and power control, which is per-PHY.
pub fn write_phys(s: &mut crate::LogLine, m: u8) {
    if m == 0 {
        let _ = s.push_str("none");
        return;
    }
    let mut first = true;
    for (bit, n) in [(0u8, "1M"), (1, "2M"), (2, "Coded")] {
        if m & (1 << bit) != 0 {
            if !first {
                let _ = s.push('/');
            }
            let _ = s.push_str(n);
            first = false;
        }
    }
}
