//! Nintendo manufacturer data (Company ID 0x0553).
//!
//! Nintendo Switch peripherals (Joy-Con, Pro Controller, and the console's own
//! LE radio) beacon a fixed-layout frame while soliciting a reconnect to their
//! last-paired host. There is no public spec, but the frame embeds that host's
//! Bluetooth address in little-endian at a fixed offset — verified against a
//! captured CONNECT_IND whose InitA matched these bytes exactly. We surface the
//! embedded host address and dump the rest.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Byte offset of the embedded little-endian reconnect-host address.
const HOST_ADDR_OFF: usize = 10;

/// Nintendo Co., Ltd. — manufacturer data (Company ID 0x0553).
pub(super) struct Nintendo;
impl super::VendorDecoder for Nintendo {
    fn company_ids(&self) -> &'static [u16] { &[0x0553] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Nintendo: len={}", body.len());
        if body.len() >= HOST_ADDR_OFF + 6 {
            // Reconnect-host address, little-endian (matches the CONNECT_IND InitA).
            let a = &body[HOST_ADDR_OFF..HOST_ADDR_OFF + 6];
            let _ = write!(
                s,
                " host≈{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                a[5], a[4], a[3], a[2], a[1], a[0]
            );
        }
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
