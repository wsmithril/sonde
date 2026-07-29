//! U-tec / ULTRALOQ smart-lock service data (`0xFF01`).
//!
//! U-tec locks (branded ULTRALOQ, "U-AC…" device names) advertise a proprietary
//! service under the 16-bit UUID `0xFF01`. The frame layout is not published: a
//! leading type byte precedes lock-state / rolling-identifier bytes that change
//! per advertisement. We label it and dump the bytes rather than guessing.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// U-tec / ULTRALOQ smart lock — service data (UUID 0xFF01).
pub(super) struct Utec;
impl super::VendorDecoder for Utec {
    fn service_uuids(&self) -> &'static [u16] { &[0xFF01] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    U-tec/ULTRALOQ 0xFF01 (lock, proprietary): type=0x{:02X} data len={}", body[0], body.len() - 1);
        emit(s);
        hexdump(&body[1..], ctx.base + 1, 6);
    }
}
