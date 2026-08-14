//! Honor device discovery (Company ID 0x09C6 and service UUID 0xFCF8).
//!
//! Honor Device Co. (Huawei spin-off) reuses Huawei's NearBy/HiLink-style
//! discovery shape. Both UUIDs are SIG-confirmed to Honor:
//! * 0x09C6 — `company_identifiers.yaml`
//! * 0xFCF7 / 0xFCF8 — `member_uuids.yaml`
//!
//! **No public byte-level RE is available** for the payloads on either UUID.
//! Payloads begin with a frame/type byte followed by rotating, opaque bytes.
//!
//! Note: many Honor phones/wearables *also* emit mfg-data under the Telink
//! chipset CID `0x0211` (SDK-default CID leaks through). Those frames are
//! decoded in [`super::telink`]; the SDK-fill signature there is a stronger
//! Honor hint than anything visible here.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Honor Device Co. — manufacturer data (0x09C6) and service data (0xFCF8).
/// Layout past the leading byte is undocumented.
pub(super) struct Honor;
impl super::VendorDecoder for Honor {
    fn company_ids(&self) -> &'static [u16] { &[0x09C6] }
    fn service_uuids(&self) -> &'static [u16] { &[0xFCF8] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let tag = match ctx.kind {
            super::FrameKind::Mfg => "Honor 0x09C6 (no public RE)",
            super::FrameKind::Service => "Honor 0xFCF8 (no public RE)",
        };
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    {}: type=0x{:02X} len={}",
            tag, body[0], body.len() - 1);
        emit(s);
        hexdump(&body[1..], ctx.base + 1, 6);
    }
}
