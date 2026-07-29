//! Eddystone beacon (service UUID 0xFEAA).
//!
//! Frame type in the first byte selects UID / URL / TLM / EID. URL frames use a
//! compact scheme + expansion encoding; EID is a rotating identifier left opaque.

use core::fmt::Write;

use super::{emit, write_hex, LogStr};

/// Eddystone — service data (UUID 0xFEAA): UID/URL/TLM/EID beacons.
pub(super) struct Eddystone;
impl super::VendorDecoder for Eddystone {
    fn service_uuids(&self) -> &'static [u16] { &[0xFEAA] }
    fn decode(&self, _ctx: &super::DecodeCtx, body: &[u8]) {
        let f = body;
        if f.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        match f[0] {
            0x00 if f.len() >= 18 => {
                // UID: tx power, 10B namespace, 6B instance.
                let _ = write!(s, "    Eddystone-UID: tx={}dBm ns=", f[1] as i8);
                write_hex(&mut s, &f[2..12]);
                let _ = write!(s, " inst=");
                write_hex(&mut s, &f[12..18]);
            }
            0x10 if f.len() >= 3 => {
                // URL: tx power, scheme prefix byte, then encoded URL bytes.
                let _ = write!(s, "    Eddystone-URL: tx={}dBm {}", f[1] as i8, Self::url_scheme(f[2]));
                for &b in &f[3..] {
                    if b <= 0x0D {
                        let _ = write!(s, "{}", Self::url_expand(b));
                    } else if (0x20..0x7F).contains(&b) {
                        let _ = write!(s, "{}", b as char);
                    } else {
                        let _ = write!(s, ".");
                    }
                }
            }
            0x20 if f.len() >= 14 => {
                // TLM: battery mV (BE), temp 8.8 fixed (BE), adv count (BE), 0.1s uptime (BE).
                let batt = u16::from_be_bytes([f[2], f[3]]);
                let temp_raw = i16::from_be_bytes([f[4], f[5]]);
                let whole = temp_raw >> 8; // signed integer part
                let frac  = ((temp_raw as i32 & 0xFF) * 100) / 256; // 0..99
                let cnt = u32::from_be_bytes([f[6], f[7], f[8], f[9]]);
                let up  = u32::from_be_bytes([f[10], f[11], f[12], f[13]]) / 10; // → seconds
                let _ = write!(s, "    Eddystone-TLM: batt={}mV temp={}.{:02}C cnt={} up={}s",
                    batt, whole, frac, cnt, up);
            }
            0x30 if f.len() >= 10 => {
                // EID: tx power + 8-byte ephemeral identifier (rotates on a timer).
                let _ = write!(s, "    Eddystone-EID: tx={}dBm eid=", f[1] as i8);
                write_hex(&mut s, &f[2..10]);
            }
            0x40 => {
                // Non-standard 0x40 frame seen in the wild on FEAA (Google Nearby /
                // proprietary EID variant): a rotating identifier with no public
                // layout. Label it rather than silently dropping it.
                let _ = write!(s, "    Eddystone 0x40 (proprietary/rotating) len=");
                let _ = write!(s, "{}: ", f.len() - 1);
                write_hex(&mut s, &f[1..]);
            }
            t => {
                let _ = write!(s, "    Eddystone: type=0x{:02X} (?) len={}", t, f.len() - 1);
            }
        }
        let _ = write!(s, "\r\n");
        emit(s);
    }
}

impl Eddystone {
    fn url_scheme(b: u8) -> &'static str {
        match b {
            0 => "http://www.",
            1 => "https://www.",
            2 => "http://",
            3 => "https://",
            _ => "",
        }
    }

    fn url_expand(b: u8) -> &'static str {
        match b {
            0x00 => ".com/", 0x01 => ".org/", 0x02 => ".edu/", 0x03 => ".net/",
            0x04 => ".info/", 0x05 => ".biz/", 0x06 => ".gov/",
            0x07 => ".com", 0x08 => ".org", 0x09 => ".edu", 0x0A => ".net",
            0x0B => ".info", 0x0C => ".biz", 0x0D => ".gov",
            _ => "",
        }
    }
}
