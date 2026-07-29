//! Tuya smart-home service data (UUID 0xFD50, Hangzhou Tuya Information Tech).
//!
//! Used by Tuya-based IoT devices (plugs, sensors, lights). The frame begins
//! with a type/version byte followed by a product/device identifier; the full
//! layout is only partially documented, so we surface the frame byte and dump
//! the identifier bytes.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Tuya IoT — service data (UUID 0xFD50).
pub(super) struct Tuya;
impl super::VendorDecoder for Tuya {
    fn service_uuids(&self) -> &'static [u16] { &[0xFD50] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Tuya 0xFD50: frame=0x{:02X} id len={}", body[0], body.len() - 1);
        emit(s);
        hexdump(&body[1..], ctx.base + 1, 6);
    }
}
