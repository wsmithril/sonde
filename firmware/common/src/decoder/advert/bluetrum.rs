//! Bluetrum (AB56xx) manufacturer data (Company ID 0x0642).
//!
//! Low-cost BLE-audio SoC vendor behind many generic earbuds/speakers. The
//! advertising frame is rotating binary state with **no public byte-level
//! RE** (searches across theengs/decoder, reelyactive advlib, Nordic bt-numbers
//! DB, and Github code search returned nothing). Vendor attribution is
//! confirmed against the SIG canonical CID registry. We label the SoC (it
//! would otherwise show as a raw vendor blob) and dump the payload — the
//! ASCII gutter often shows an embedded firmware/build string.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Bluetrum Technology — manufacturer data (Company ID 0x0642).
pub(super) struct Bluetrum;
impl super::VendorDecoder for Bluetrum {
    fn company_ids(&self) -> &'static [u16] { &[0x0642] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Bluetrum SoC: type=0x{:02X} len={}", body[0], body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
