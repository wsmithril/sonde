//! Hisense smart-life service data (`0xF005`).
//!
//! Hisense appliances (e.g. the `HIS-242a` AC) advertise a state frame under the
//! 16-bit UUID `0xF005`. The layout is not published — from the app decompile,
//! appliance control runs over the Hi-Smart cloud + MQTT plane, so the BLE frame
//! is identity/state. We label it and dump the bytes rather than guessing.

use core::fmt::Write;

use super::{LogStr, emit, hexdump};

/// Hisense smart-life appliance — service data (UUID 0xF005).
pub(super) struct Hisense;
impl super::VendorDecoder for Hisense {
    fn service_uuids(&self) -> &'static [u16] {
        &[0xF005]
    }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() {
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(
            s,
            "    Hisense 0xF005 (appliance state): type=0x{:02X} len={}",
            body[0],
            body.len().saturating_sub(1)
        );
        emit(s);
        hexdump(&body[1..], ctx.base + 1, 6);
    }
}
