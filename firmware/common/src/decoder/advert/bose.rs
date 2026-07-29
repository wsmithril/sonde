//! Bose manufacturer data (Company ID 0x009E).
//!
//! Bose publishes no advertising spec; the layout below is read off captured
//! traffic and is best-effort. Every observed frame is 9 bytes and begins with a
//! zero byte, then a status byte, then a frame type (0x06 and 0x26 seen), then a
//! 6-byte identifier that differs in every frame — so it carries no stable
//! handle and is reported as an opaque field.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Bose Corporation — manufacturer data (Company ID 0x009E).
pub(super) struct Bose;
impl super::VendorDecoder for Bose {
    fn company_ids(&self) -> &'static [u16] { &[0x009E] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 9 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Bose (unofficial): status=0x{:02X} type=0x{:02X} id=",
            body[1], body[2]);
        write_hex(&mut s, &body[3..9]);
        emit(s);
        if body.len() > 9 {
            hexdump(&body[9..], ctx.base + 9, 6);
        }
    }
}
