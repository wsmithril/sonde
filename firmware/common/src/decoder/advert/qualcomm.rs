//! Qualcomm/CSR manufacturer data (Company ID 0x000A).
//!
//! Observed frames are 20 bytes and open with the ASCII tag "GB" or "GF"
//! followed by a zero byte and a one-byte counter, then 16 bytes that change
//! every frame. The tag and counter are decoded; the 16-byte block is reported
//! as an opaque rotating field.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Qualcomm Technologies International (QTIL) — manufacturer data (0x000A).
pub(super) struct Qualcomm;
impl super::VendorDecoder for Qualcomm {
    fn company_ids(&self) -> &'static [u16] { &[0x000A] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 4 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Qualcomm (unofficial): tag=\"{}{}\" flags=0x{:02X} cnt=0x{:02X}",
            body[0] as char, body[1] as char, body[2], body[3]);
        if body.len() > 4 {
            let _ = write!(s, " rotating=");
            write_hex(&mut s, &body[4..]);
        }
        emit(s);
    }
}
