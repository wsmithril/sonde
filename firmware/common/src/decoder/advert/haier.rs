//! Haier U-home manufacturer data (Company ID 0x0929).
//!
//! Air conditioners, water heaters and gateways advertise a 13-byte frame:
//! type 0x10, two zero bytes, the appliance's 6-byte address in display order,
//! a two-byte version and a little-endian product code (0x03E9 on every unit
//! seen). Reverse-engineered from captures.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Qingdao Haier Technology — manufacturer data (Company ID 0x0929).
pub(super) struct Haier;
impl super::VendorDecoder for Haier {
    fn company_ids(&self) -> &'static [u16] { &[0x0929] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 13 || body[0] != 0x10 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Haier U-home: addr=");
        super::write_mac_be(&mut s, &body[3..9]);
        let _ = write!(s, " ver={}.{} product={}",
            body[9], body[10], u16::from_le_bytes([body[11], body[12]]));
        emit(s);
        super::emit_oui_vendor(&body[3..9]);
        if body.len() > 13 { hexdump(&body[13..], ctx.base + 13, 6); }
    }
}
