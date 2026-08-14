//! Ninebot/Segway electric scooter BLE manufacturer data (Company ID 0x06D1).
//!
//! Ninebot advertises with Company ID 0x06D1 (Ninebot Inc.) and a short payload
//! that encodes the model type and a partial device ID. The GATT channel uses the
//! Nordic UART Service (6E400001-…) or a custom variant with "ninebot" embedded in
//! the UUID. Protocol framing over UART: `5A A5 | bLen | src | dst | cmd | arg |
//! payload[bLen] | CRC16`. Source: BruceDevices/firmware ble_ninebot.cpp.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

pub(super) struct Ninebot;
impl super::VendorDecoder for Ninebot {
    fn company_ids(&self) -> &'static [u16] { &[0x06D1] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() {
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Ninebot: frame=0x{:02X} len={}", body[0], body.len());
        emit(s);
        if body.len() > 1 {
            hexdump(&body[1..], ctx.base + 1, 6);
        }
    }
}
