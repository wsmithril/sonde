//! AR Timing manufacturer data (Company ID 0x0201).
//!
//! Race-timing transponders advertise a 21-byte frame carrying the tag's own
//! 6-byte address in display order, a frame type, a battery percentage, and a
//! fixed `01 09 08` firmware/mode block followed by a zero-padded tail.
//! Reverse-engineered from captures.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// AR Timing — manufacturer data (Company ID 0x0201).
pub(super) struct ArTiming;
impl super::VendorDecoder for ArTiming {
    fn company_ids(&self) -> &'static [u16] { &[0x0201] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 11 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    AR Timing: tag=");
        super::write_mac_be(&mut s, &body[0..6]);
        let _ = write!(s, " type=0x{:02X} battery={}% mode={}.{}.{}",
            body[6], body[7], body[8], body[9], body[10]);
        emit(s);
        super::emit_oui_vendor(&body[0..6]);
    }
}
