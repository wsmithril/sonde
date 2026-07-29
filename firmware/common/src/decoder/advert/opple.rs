//! OPPLE Lighting manufacturer data (Company ID 0x0539).
//!
//! OPPLE smart lighting uses a BLE-mesh based ecosystem; its advertising frames
//! carry a leading frame byte plus rotating mesh/state bytes with no public
//! layout. We label the source (it would otherwise show as a raw vendor blob)
//! and dump the payload.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// OPPLE Lighting — manufacturer data (Company ID 0x0539).
pub(super) struct Opple;
impl super::VendorDecoder for Opple {
    fn company_ids(&self) -> &'static [u16] { &[0x0539] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    OPPLE Lighting (BLE mesh): frame=0x{:02X} len={}", body[0], body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
