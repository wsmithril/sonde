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
        let _ = write!(s, "    Samsung ({}): type=0x{:02X} len={}",
            Self::family(body[0]), body[0], body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}

impl Samsung {
    /// Galaxy manufacturer-data frame family, keyed on the leading byte. The
    /// per-model color IDs inside the Buds/Watch "EasySetup" frames need a
    /// device table that is not carried here, so only the family is named; the
    /// body stays as hex. (SmartTag / SmartThings-Find offline-finding rides
    /// service UUIDs FD59/FD5A, not this Company-ID 0x0075 frame.)
    fn family(t: u8) -> &'static str {
        match t {
            0x42 => "Galaxy Buds EasySetup",
            0x01 => "Galaxy Watch/EasySetup",
            _ => "Galaxy",
        }
    }
}
