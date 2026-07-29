//! HP service data (UUID 0xFDF7).
//!
//! Advertised by HP printers/PCs for proximity setup ("HP Smart"). The frame is
//! a leading type byte plus rotating identifier bytes with no public layout; we
//! label it and dump the payload.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// HP, Inc. — service data (UUID 0xFDF7).
pub(super) struct Hp;
impl super::VendorDecoder for Hp {
    fn service_uuids(&self) -> &'static [u16] { &[0xFDF7] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    HP 0xFDF7: type=0x{:02X} len={}", body[0], body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
