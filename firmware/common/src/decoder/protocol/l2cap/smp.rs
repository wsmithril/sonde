//! Security Manager Protocol, L2CAP CID 0x0006 (Core v5.4 Vol 3 Part H).
//!
//! The pairing exchange is plaintext up to the point where the keys it
//! negotiates take effect, so the parameters that decide *how* strong the
//! resulting link is — association model, key size, what gets distributed — are
//! all readable here.

use core::fmt::Write;

use super::{line, send, u16le, write_hex_be, write_hex_capped, Decoder};

pub struct Smp;

impl Decoder<u16> for Smp {
    fn keys(&self) -> &'static [u16] {
        &[0x0006]
    }

    fn decode(&self, d: &[u8]) {
        let op = d[0];
        crate::ulogf!("  SMP {} (0x{:02X})\r\n", Self::name(op), op);
        let p = &d[1..];
        match op {
            // Pairing Req / Rsp: IOCap OOB AuthReq MaxKeySize InitKeyDist
            // RespKeyDist. AuthReq's MITM and SC bits are what separate an
            // authenticated LE Secure Connections pairing from Just Works.
            0x01 | 0x02 if p.len() >= 6 => {
                let mut s = line();
                let auth = p[2];
                let _ = write!(
                    s,
                    "iocap={} ({}) oob={} max_key={}B bonding={} mitm={} sc={} keypress={} ct2={}",
                    p[0], Self::io_cap_name(p[0]), p[1], p[3],
                    auth & 0x03, (auth >> 2) & 1, (auth >> 3) & 1, (auth >> 4) & 1, (auth >> 5) & 1
                );
                send(s);
                let mut s = line();
                let _ = s.push_str("init_keys=");
                Self::write_keys(&mut s, p[4]);
                let _ = s.push_str(" resp_keys=");
                Self::write_keys(&mut s, p[5]);
                send(s);
            }
            // Pairing Failed: the single reason byte.
            0x05 if !p.is_empty() => {
                let mut s = line();
                let _ = write!(s, "reason=0x{:02X} ({})", p[0], Self::fail_reason(p[0]));
                send(s);
            }
            // Central Identification: EDIV(2) Rand(8) — the handle for the LTK
            // that was just distributed, and what a later LL_ENC_REQ will name.
            0x07 if p.len() >= 10 => {
                let mut s = line();
                let _ = write!(s, "ediv=0x{:04X} rand=", u16le(p, 0));
                write_hex_be(&mut s, &p[2..10]);
                send(s);
            }
            // Identity Address Information: AddrType(1) BD_ADDR(6) — the peer's
            // permanent address, handed over in the clear at the end of pairing
            // however private its advertising address was.
            0x09 if p.len() >= 7 => {
                let mut s = line();
                let _ = write!(
                    s, "addr_type={} addr=", if p[0] == 0 { "public" } else { "random" });
                for (i, b) in p[1..7].iter().rev().enumerate() {
                    if i > 0 {
                        let _ = s.push(':');
                    }
                    let _ = write!(s, "{:02X}", b);
                }
                send(s);
            }
            // Security Req: AuthReq only.
            0x0B if !p.is_empty() => {
                let mut s = line();
                let _ = write!(
                    s, "bonding={} mitm={} sc={} keypress={}",
                    p[0] & 0x03, (p[0] >> 2) & 1, (p[0] >> 3) & 1, (p[0] >> 4) & 1
                );
                send(s);
            }
            // The remaining commands carry one fixed-size opaque value: a
            // confirm, a nonce, a key, or a public key. Length identifies which.
            0x03 | 0x04 | 0x06 | 0x08 | 0x0A | 0x0C | 0x0D if !p.is_empty() => {
                let mut s = line();
                let _ = write!(s, "value[{}B]=", p.len());
                write_hex_capped(&mut s, p, 32);
                send(s);
            }
            _ => {}
        }
    }
}

/// Names, association-model tables and key flags the SMP arms share.
impl Smp {
    /// Security Manager command names.
    fn name(op: u8) -> &'static str {
        match op {
            0x01 => "Pairing Req",
            0x02 => "Pairing Rsp",
            0x03 => "Pairing Confirm",
            0x04 => "Pairing Random",
            0x05 => "Pairing Failed",
            0x06 => "Encryption Information",
            0x07 => "Central Identification",
            0x08 => "Identity Information",
            0x09 => "Identity Address Information",
            0x0A => "Signing Information",
            0x0B => "Security Req",
            0x0C => "Pairing Public Key",
            0x0D => "Pairing DHKey Check",
            0x0E => "Pairing Keypress Notification",
            _ => "?",
        }
    }

    /// IO capability, which with the peer's choice fixes the association model.
    fn io_cap_name(v: u8) -> &'static str {
        match v {
            0x00 => "DisplayOnly",
            0x01 => "DisplayYesNo",
            0x02 => "KeyboardOnly",
            0x03 => "NoInputNoOutput",
            0x04 => "KeyboardDisplay",
            _ => "?",
        }
    }

    /// Reason codes for Pairing Failed.
    fn fail_reason(v: u8) -> &'static str {
        match v {
            0x01 => "passkey-entry-failed",
            0x02 => "oob-not-available",
            0x03 => "authentication-requirements",
            0x04 => "confirm-value-failed",
            0x05 => "pairing-not-supported",
            0x06 => "encryption-key-size",
            0x07 => "command-not-supported",
            0x08 => "unspecified-reason",
            0x09 => "repeated-attempts",
            0x0A => "invalid-parameters",
            0x0B => "dhkey-check-failed",
            0x0C => "numeric-comparison-failed",
            0x0D => "bredr-pairing-in-progress",
            0x0E => "cross-transport-key-derivation-not-allowed",
            0x0F => "key-rejected",
            _ => "?",
        }
    }

    /// Append the key-distribution flags of an initiator/responder key field.
    fn write_keys(s: &mut crate::LogLine, v: u8) {
        if v & 0x0F == 0 {
            let _ = s.push_str("none");
            return;
        }
        let mut first = true;
        for (bit, n) in [(0u8, "LTK"), (1, "IRK"), (2, "CSRK"), (3, "LinkKey")] {
            if v & (1 << bit) != 0 {
                if !first {
                    let _ = s.push('/');
                }
                let _ = s.push_str(n);
                first = false;
            }
        }
    }
}
