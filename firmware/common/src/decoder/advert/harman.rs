//! Harman / JBL service data (UUID 0xFDDF).
//!
//! Advertised by Harman-owned audio brands (JBL, Harman Kardon, AKG) for app
//! pairing. The short frame is rotating state with no public layout; we label it
//! and dump the payload.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Harman International — service data (UUID 0xFDDF).
pub(super) struct Harman;
impl super::VendorDecoder for Harman {
    fn service_uuids(&self) -> &'static [u16] { &[0xFDDF] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Harman/JBL 0xFDDF: len={}", body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
