//! Edifier manufacturer data (Company ID 0x07E0).
//!
//! Observed frames begin with the device's 6-byte Bluetooth Classic MAC address
//! (a stable, non-rotating identifier — unlike the BLE resolvable private
//! address) followed by a couple of state bytes. The classic MAC is the useful
//! field; the rest is labelled and kept inline.

use core::fmt::Write;

use super::{emit, write_hex, LogStr};

/// Edifier — manufacturer data (Company ID 0x07E0).
pub(super) struct Edifier;
impl super::VendorDecoder for Edifier {
    fn company_ids(&self) -> &'static [u16] { &[0x07E0] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 6 {
            super::hexdump(body, ctx.base, 6);
            return;
        }
        let m = &body[..6];
        let mut s: LogStr = LogStr::new();
        let _ = write!(s,
            "    Edifier: classic-MAC={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} state=",
            m[0], m[1], m[2], m[3], m[4], m[5]);
        write_hex(&mut s, &body[6..]);
        emit(s);
    }
}
