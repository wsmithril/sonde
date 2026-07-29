//! Texas Instruments manufacturer data (Company ID 0x000D).
//!
//! TI ships this Company ID in its SimpleLink SDK examples, so the frames come
//! from whatever product an integrator built rather than from one format. Two
//! shapes appear in captures: a printable ASCII tag (a board/build identifier
//! such as "CRF3A71ADV"), and a binary frame opening with 0x01 and a subtype
//! byte followed by a 4-byte identifier.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Texas Instruments Inc. — manufacturer data (Company ID 0x000D).
pub(super) struct TexasInstruments;
impl super::VendorDecoder for TexasInstruments {
    fn company_ids(&self) -> &'static [u16] { &[0x000D] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        if body.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
            let _ = write!(s, "    TI: tag=\"");
            for &b in body { let _ = s.push(b as char); }
            let _ = write!(s, "\"");
            emit(s);
        } else if body.len() >= 6 && body[0] == 0x01 {
            let _ = write!(s, "    TI: v1 subtype=0x{:02X} id=", body[1]);
            write_hex(&mut s, &body[2..6]);
            emit(s);
            if body.len() > 6 { hexdump(&body[6..], ctx.base + 6, 6); }
        } else {
            let _ = write!(s, "    TI: len={}", body.len());
            emit(s);
            hexdump(body, ctx.base, 6);
        }
    }
}
