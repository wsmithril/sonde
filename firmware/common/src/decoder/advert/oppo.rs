//! OPPO manufacturer data (Company ID 0x079A).
//!
//! OPPO phones/earbuds advertise an "ONet"/fast-connect discovery frame: a
//! leading frame byte followed by mostly binary, rotating state with no public
//! layout. We label it and dump the full bytes.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// OPPO — manufacturer data (Company ID 0x079A).
pub(super) struct Oppo;
impl super::VendorDecoder for Oppo {
    fn company_ids(&self) -> &'static [u16] { &[0x079A] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    OPPO (fast-connect): frame=0x{:02X} len={}", body[0], body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
