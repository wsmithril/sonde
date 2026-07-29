//! Huawei device discovery (service `0xFDEE` and Company ID `0x027D`).
//!
//! Used by Huawei "HiLink"/HarmonyOS ("OneHop"/NearLink) discovery. Both the
//! service-data frame (0xFDEE) and the manufacturer frame (0x027D) begin with a
//! frame/type byte followed by rotating, undocumented identifier bytes, so we
//! surface only the frame byte and label the rest — it would otherwise show as
//! an opaque "Huawei" blob.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Huawei — service data (UUID 0xFDEE) and manufacturer data (Company ID 0x027D):
/// HiLink / HarmonyOS discovery.
pub(super) struct Huawei;
impl super::VendorDecoder for Huawei {
    fn company_ids(&self) -> &'static [u16] { &[0x027D] }
    fn service_uuids(&self) -> &'static [u16] { &[0xFDEE] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let tag = match ctx.kind {
            super::FrameKind::Mfg => "Huawei 0x027D",
            super::FrameKind::Service => "Huawei 0xFDEE",
        };
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    {}: type=0x{:02X} ({}) data len={}",
            tag, body[0], Self::frame_name(body[0]), body.len() - 1);
        emit(s);
        hexdump(&body[1..], ctx.base + 1, 6);
    }
}

impl Huawei {
    /// Known HarmonyOS/HiLink frame-type bytes. Only 0x01 (device discovery) is
    /// confidently identified from captures; others are labelled "?".
    fn frame_name(t: u8) -> &'static str {
        match t {
            0x01 => "device discovery",
            _ => "?",
        }
    }
}
