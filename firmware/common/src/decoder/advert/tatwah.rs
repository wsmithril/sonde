//! tatwah SA manufacturer data (Company ID 0x0818).
//!
//! Observed on devices advertising the names `KeepBL-9A` / `KeepBL-0E` /
//! `KeepBL-1A` — a small fleet of asset-tracking beacons. 9-byte frame, no
//! public spec; read off captures:
//!
//! ```text
//! 12 | C4 59 | 72 9D 9A | 35 03 00
//! ^^   ^^^^^   ^^^^^^^^   ^^^^^^^^ near-constant trailer (fw/type)
//! type  group   per-unit id
//! ```
//!
//! The per-unit bytes are what differ between the `KeepBL-*` units seen together,
//! so they are the beacon's identity; the trailer is the same across all of them.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// tatwah SA — manufacturer data (Company ID 0x0818): "KeepBL" asset beacons.
pub(super) struct Tatwah;
impl super::VendorDecoder for Tatwah {
    fn company_ids(&self) -> &'static [u16] { &[0x0818] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 9 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    tatwah beacon (unofficial): type=0x{:02X} group=", body[0]);
        write_hex(&mut s, &body[1..3]);
        let _ = write!(s, " id=");
        write_hex(&mut s, &body[3..6]);
        let _ = write!(s, " tail=");
        write_hex(&mut s, &body[6..9]);
        emit(s);
    }
}
