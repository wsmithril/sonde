//! Lucimed manufacturer data (Company ID 0x0901).
//!
//! Lucimed makes the Luminette light-therapy glasses. In captures this ID also
//! appears alongside a speaker advertising `LE-Vivian bose`, so the emitting
//! product is not certain — the frame shape is reported without claiming a model.
//!
//! 13-byte frame, no public spec; read off captures:
//!
//! ```text
//! 76 12 | 94 01 F0 9F 13 7D FA 12 17 F1 9A
//! ^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ payload, near-static per unit
//! constant header
//! ```
//!
//! The `76 12` header is constant on every observed frame; the remainder shows
//! only a handful of distinct values across a whole capture, i.e. a fixed-identity
//! beacon rather than changing telemetry.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Lucimed — manufacturer data (Company ID 0x0901).
pub(super) struct Lucimed;
impl super::VendorDecoder for Lucimed {
    fn company_ids(&self) -> &'static [u16] { &[0x0901] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 3 || body[0] != 0x76 || body[1] != 0x12 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Lucimed (unofficial): hdr=7612 payload=");
        write_hex(&mut s, &body[2..]);
        emit(s);
    }
}
