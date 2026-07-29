//! Samsung manufacturer data (Company ID 0x0075).
//!
//! Used by Galaxy phones/wearables and SmartThings devices. The frame begins
//! with a type byte followed by rotating, largely undocumented state (SmartThings
//! onboarding, Galaxy quick-connect). We label it and dump the payload.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Samsung Electronics — manufacturer data (Company ID 0x0075).
pub(super) struct Samsung;
impl super::VendorDecoder for Samsung {
    fn company_ids(&self) -> &'static [u16] { &[0x0075] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Samsung: type=0x{:02X} len={}", body[0], body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
