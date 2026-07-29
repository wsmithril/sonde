//! Audio-Technica manufacturer data (Company ID 0x0618).
//!
//! Observed on `LE_ATH-SQ1TW2` and `LE_ATH-CKS50TW` earbuds. Two frame shapes,
//! selected by the leading type byte; no public spec:
//!
//! ```text
//! type 0x01: 01 00 15                    — 3 bytes, entirely constant: a bare
//!                                          "an ATH device is present" beacon
//! type 0x03: 03 00 0A [id×4]             — 7 bytes: header + per-unit identifier
//! ```
//!
//! Neither frame carries battery or state; the model lives in the advertised
//! name (`LE_ATH-…`), so this decoder names the frame shape and surfaces the id.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Audio-Technica Corporation — manufacturer data (Company ID 0x0618).
pub(super) struct AudioTechnica;
impl super::VendorDecoder for AudioTechnica {
    fn company_ids(&self) -> &'static [u16] { &[0x0618] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() {
            return;
        }
        let mut s: LogStr = LogStr::new();
        match body[0] {
            0x01 if body.len() >= 3 => {
                let _ = write!(s, "    Audio-Technica (unofficial): presence beacon (0x{:02X}{:02X}{:02X})",
                    body[0], body[1], body[2]);
                emit(s);
            }
            0x03 if body.len() >= 7 => {
                let _ = write!(s, "    Audio-Technica (unofficial): type=0x03 id=");
                write_hex(&mut s, &body[3..7]);
                emit(s);
            }
            _ => {
                let _ = write!(s, "    Audio-Technica (unofficial): type=0x{:02X} len={}", body[0], body.len());
                emit(s);
                hexdump(body, ctx.base, 6);
            }
        }
    }
}
