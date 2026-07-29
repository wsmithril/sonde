//! Zhuhai Jieli (JieLi/AC69xx) manufacturer data (Company ID 0x05D6).
//!
//! Jieli is a very common audio SoC vendor behind many no-name earbuds/speakers.
//! Its default frame carries a leading type byte plus rotating state and, on some
//! builds, an embedded ASCII model string. We label the SoC; the hexdump's ASCII
//! gutter shows any text.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Zhuhai Jieli Technology — manufacturer data (Company ID 0x05D6).
pub(super) struct Jieli;
impl super::VendorDecoder for Jieli {
    fn company_ids(&self) -> &'static [u16] { &[0x05D6] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Jieli SoC: type=0x{:02X} len={}", body[0], body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
