//! vivo manufacturer data (Company ID 0x0837).
//!
//! vivo / iQOO phones and earbuds advertise a fast-connect discovery frame that
//! embeds a short ASCII model hint (e.g. "vivmin") alongside rotating binary
//! state. The layout is undocumented; we label it and dump the bytes, whose
//! ASCII gutter shows the model hint.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// vivo — manufacturer data (Company ID 0x0837).
pub(super) struct Vivo;
impl super::VendorDecoder for Vivo {
    fn company_ids(&self) -> &'static [u16] { &[0x0837] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    vivo (fast-connect): frame=0x{:02X} len={}", body[0], body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
