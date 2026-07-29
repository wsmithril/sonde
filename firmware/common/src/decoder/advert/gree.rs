//! GREE air-conditioner manufacturer data (Company ID 0x0D23).
//!
//! Frames open with `00 02 01`, carry the appliance's own 6-byte address in
//! display order (verified against the packet header of the same frame), then a
//! state byte and a zero-padded tail. Reverse-engineered from captures.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// GREE Electric Appliances — manufacturer data (Company ID 0x0D23).
pub(super) struct Gree;
impl super::VendorDecoder for Gree {
    fn company_ids(&self) -> &'static [u16] { &[0x0D23] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 10 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    GREE: ver={}.{} addr=", body[1], body[2]);
        super::write_mac_be(&mut s, &body[3..9]);
        let _ = write!(s, " state=0x{:02X}", body[9]);
        emit(s);
        super::emit_oui_vendor(&body[3..9]);
    }
}
