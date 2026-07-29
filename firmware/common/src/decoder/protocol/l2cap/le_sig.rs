//! LE L2CAP signalling, CID 0x0005 (Core v5.4 Vol 3 Part A §4).
//!
//! Each command is a 4-byte header — code, identifier, payload length — then the
//! payload. On LE this channel carries the peripheral's request to change
//! connection parameters and the setup for credit-based data channels.

use core::fmt::Write;

use super::{line, send, u16le, write_interval, Decoder};

pub struct LeSig;

impl Decoder<u16> for LeSig {
    fn keys(&self) -> &'static [u16] {
        &[0x0005]
    }

    fn decode(&self, d: &[u8]) {
        let op = d[0];
        if d.len() < 4 {
            crate::ulogf!("  LE_SIG {} (0x{:02X}) truncated\r\n", Self::name(op), op);
            return;
        }
        crate::ulogf!(
            "  LE_SIG {} (0x{:02X}) id={} plen={}\r\n", Self::name(op), op, d[1], u16le(d, 2));
        let p = &d[4..];
        match op {
            // Disconnection Req / Rsp: the two channel endpoints.
            0x06 | 0x07 if p.len() >= 4 => {
                let mut s = line();
                let _ = write!(s, "dcid=0x{:04X} scid=0x{:04X}", u16le(p, 0), u16le(p, 2));
                send(s);
            }
            // Connection Parameter Update Req: the peripheral asking the central
            // for a different interval. The central answers by starting an
            // LL_CONNECTION_UPDATE_IND procedure, so this is the earliest
            // warning in a capture that the timeline is about to move.
            0x12 if p.len() >= 8 => {
                let mut s = line();
                let _ = s.push_str("interval=");
                write_interval(&mut s, u16le(p, 0));
                let _ = s.push_str("..");
                write_interval(&mut s, u16le(p, 2));
                let _ = write!(
                    s, " latency={} timeout={}ms", u16le(p, 4), u16le(p, 6) as u32 * 10);
                send(s);
            }
            0x13 if p.len() >= 2 => {
                let mut s = line();
                let r = u16le(p, 0);
                let _ = write!(
                    s, "result={} ({})", r, if r == 0 { "accepted" } else { "rejected" });
                send(s);
            }
            // LE Credit Based Connection Req: SPSM, source CID, MTU, MPS, and
            // the initial credit grant.
            0x14 if p.len() >= 10 => {
                let mut s = line();
                let _ = write!(
                    s, "spsm=0x{:04X} scid=0x{:04X} mtu={} mps={} credits={}",
                    u16le(p, 0), u16le(p, 2), u16le(p, 4), u16le(p, 6), u16le(p, 8)
                );
                send(s);
            }
            0x15 if p.len() >= 10 => {
                let mut s = line();
                let res = u16le(p, 8);
                let _ = write!(
                    s, "dcid=0x{:04X} mtu={} mps={} credits={} result=0x{:04X} ({})",
                    u16le(p, 0), u16le(p, 2), u16le(p, 4), u16le(p, 6), res, Self::conn_result(res)
                );
                send(s);
            }
            // Flow Control Credit Ind: more credits for one channel.
            0x16 if p.len() >= 4 => {
                let mut s = line();
                let _ = write!(s, "cid=0x{:04X} credits=+{}", u16le(p, 0), u16le(p, 2));
                send(s);
            }
            _ => {}
        }
    }
}

/// Command names and result codes the LE signalling arms share.
impl LeSig {
    /// LE signalling command names.
    fn name(op: u8) -> &'static str {
        match op {
            0x01 => "Command Reject",
            0x06 => "Disconnection Req",
            0x07 => "Disconnection Rsp",
            0x12 => "Connection Parameter Update Req",
            0x13 => "Connection Parameter Update Rsp",
            0x14 => "LE Credit Based Connection Req",
            0x15 => "LE Credit Based Connection Rsp",
            0x16 => "Flow Control Credit Ind",
            0x17 => "Credit Based Connection Req",
            0x18 => "Credit Based Connection Rsp",
            _ => "?",
        }
    }

    /// Result codes for the credit-based connection responses.
    fn conn_result(v: u16) -> &'static str {
        match v {
            0x0000 => "success",
            0x0002 => "spsm-not-supported",
            0x0004 => "no-resources",
            0x0005 => "insufficient-authentication",
            0x0006 => "insufficient-authorization",
            0x0007 => "insufficient-key-size",
            0x0008 => "insufficient-encryption",
            0x0009 => "invalid-source-cid",
            0x000A => "source-cid-already-allocated",
            0x000B => "unacceptable-parameters",
            _ => "?",
        }
    }
}
