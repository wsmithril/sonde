//! Manufacturer data under Company ID 0x0058 (assigned to Vizio, Inc.).
//!
//! In captures this ID is emitted by devices advertising the name
//! `JBL TUNE BUDS-LE` — i.e. the frame is produced by JBL earbud firmware using
//! the 0x0058 company ID, not by a Vizio product. We name the assigned owner
//! (that is what the ID means) and note the observed product in the log line so
//! the mismatch is visible rather than silently mis-attributed.
//!
//! Layout, read off captures (no public spec):
//!
//! ```text
//! 73 0F | 00 00 | 33 69 6F 18 72 40 | 00 00 00 00 00 00
//! ^^^^^   flags   ^^^^^^^^^^^^^^^^^  zero padding
//! header          6-byte device id (stable per unit)
//! ```

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Vizio, Inc. (Company ID 0x0058) — in practice JBL TWS earbud frames.
pub(super) struct Vizio;
impl super::VendorDecoder for Vizio {
    fn company_ids(&self) -> &'static [u16] { &[0x0058] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 10 || body[0] != 0x73 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    0x0058 (unofficial, seen on JBL TWS): hdr=0x{:02X}{:02X} flags=0x{:02X}{:02X} id=",
            body[0], body[1], body[2], body[3]);
        write_hex(&mut s, &body[4..10]);
        // The tail is zero padding on every observed frame; call out any that is not.
        if body.len() > 10 && body[10..].iter().any(|&b| b != 0) {
            let _ = write!(s, " tail=");
            write_hex(&mut s, &body[10..]);
        }
        emit(s);
    }
}
