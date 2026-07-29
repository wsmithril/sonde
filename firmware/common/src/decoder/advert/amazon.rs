//! Amazon service data (UUID 0xFE03).
//!
//! Advertised by Amazon devices (Echo, Fire TV, Ring, Kindle) during Wi-Fi
//! Simple Setup / Frustration-Free Setup. The frame carries rotating onboarding
//! state with no public layout; we label it and dump the payload.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Amazon.com Services — service data (UUID 0xFE03).
pub(super) struct Amazon;
impl super::VendorDecoder for Amazon {
    fn service_uuids(&self) -> &'static [u16] { &[0xFE03] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Amazon 0xFE03 (device setup): len={}", body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
