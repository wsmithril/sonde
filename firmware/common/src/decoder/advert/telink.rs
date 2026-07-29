//! Telink manufacturer data (Company ID 0x0211).
//!
//! Telink is the SoC vendor behind a large long tail of inexpensive earbuds,
//! remotes, and mesh nodes; their default advertising frame commonly embeds an
//! ASCII firmware/build string (e.g. "LiU-1.0.2"), which the hexdump's ASCII
//! gutter shows. We label the SoC.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Telink Semiconductor — manufacturer data (Company ID 0x0211).
pub(super) struct Telink;
impl super::VendorDecoder for Telink {
    fn company_ids(&self) -> &'static [u16] { &[0x0211] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Telink SoC: len={}", body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
