//! Yichip Microelectronics manufacturer data (Company ID 0x050E).
//!
//! Yichip (Hangzhou) is a BLE-SoC vendor (YC-series chips). Vendor
//! attribution is SIG-confirmed. Observed frames are two bytes — a product
//! code and a revision — with no payload beyond that, so the whole frame is
//! a beacon-presence marker. **No public byte-level RE** maps product codes
//! to Yichip chip families, so we surface the raw bytes only.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Yichip Microelectronics — manufacturer data (Company ID 0x050E).
pub(super) struct Yichip;
impl super::VendorDecoder for Yichip {
    fn company_ids(&self) -> &'static [u16] { &[0x050E] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() != 2 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Yichip: product=0x{:02X} rev=0x{:02X}", body[0], body[1]);
        emit(s);
    }
}
