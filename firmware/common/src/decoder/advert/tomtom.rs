//! TomTom manufacturer data (Company ID 0x0100).
//!
//! Observed frames are 20 bytes with a fixed `B5 00` header, a frame type byte,
//! then a 4-byte identifier that stays the same across a device's frames and a
//! 4-byte block that changes every frame, ending in a constant `01 10 00 00 00`
//! trailer. Reverse-engineered from captures; TomTom publishes no spec.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// TomTom International BV — manufacturer data (Company ID 0x0100).
pub(super) struct TomTom;
impl super::VendorDecoder for TomTom {
    fn company_ids(&self) -> &'static [u16] { &[0x0100] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 15 || body[0] != 0xB5 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    TomTom (unofficial): type=0x{:02X} id=", body[2]);
        write_hex(&mut s, &body[3..7]);
        let _ = write!(s, " rotating=");
        write_hex(&mut s, &body[11..15]);
        emit(s);
        hexdump(&body[7..11], ctx.base + 7, 6);
    }
}
