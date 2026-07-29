//! Honor device discovery (Company ID 0x09C6 and service UUID 0xFCF8).
//!
//! Honor spun out of Huawei and reuses the same NearLink/"HiLink"-style discovery
//! shape: a leading frame/type byte followed by rotating, undocumented identifier
//! bytes. Both the manufacturer frame (0x09C6) and the service-data frame (0xFCF8)
//! are handled here; we surface the frame byte and label the rest (it would
//! otherwise show as an opaque "Honor Device" blob).

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Honor Device Co. — manufacturer data (0x09C6) and service data (0xFCF8).
pub(super) struct Honor;
impl super::VendorDecoder for Honor {
    fn company_ids(&self) -> &'static [u16] { &[0x09C6] }
    fn service_uuids(&self) -> &'static [u16] { &[0xFCF8] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let tag = match ctx.kind {
            super::FrameKind::Mfg => "Honor 0x09C6",
            super::FrameKind::Service => "Honor 0xFCF8",
        };
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    {}: type=0x{:02X} rotating len={}", tag, body[0], body.len() - 1);
        emit(s);
        hexdump(&body[1..], ctx.base + 1, 6);
    }
}
