//! Shokz manufacturer data (Company ID 0x0CAC).
//!
//! Shokz open-ear headphones (observed: "OpenFit Air by Shokz") emit a 6-byte
//! frame. No public spec. The width and the low per-byte variance across a
//! capture's units are consistent with a **device address / pairing handle**
//! rather than telemetry — there is no battery or state field to read here, so
//! the six bytes are reported as one identifier.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Shenzhen Shokz Co., Ltd. — manufacturer data (Company ID 0x0CAC).
pub(super) struct Shokz;
impl super::VendorDecoder for Shokz {
    fn company_ids(&self) -> &'static [u16] { &[0x0CAC] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 6 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Shokz (unofficial): id=");
        write_hex(&mut s, &body[0..6]);
        if body.len() > 6 {
            let _ = write!(s, " +{}B", body.len() - 6);
        }
        emit(s);
        if body.len() > 6 {
            hexdump(&body[6..], ctx.base + 6, 6);
        }
    }
}
