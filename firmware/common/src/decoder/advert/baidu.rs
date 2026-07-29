//! Baidu service data (`0xFDC2`, Baidu Online Network Technology (Beijing) Co.).
//!
//! 0xFDC2 is Baidu's Bluetooth SIG *member* UUID — it identifies the Baidu BLE
//! SDK (DuerOS voice / device provisioning), not the hardware maker. Third-party
//! OEMs (e.g. the Newman / 纽曼 M16 voice recorder) embed that SDK, so the OEM in
//! the device name and the UUID owner differ. The frame layout is undocumented,
//! so we surface the leading frame byte and hexdump the rest.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Baidu — service data (UUID 0xFDC2): DuerOS / device-provisioning SDK.
pub(super) struct Baidu;
impl super::VendorDecoder for Baidu {
    fn service_uuids(&self) -> &'static [u16] { &[0xFDC2] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Baidu 0xFDC2: frame=0x{:02X} data len={}", body[0], body.len() - 1);
        emit(s);
        hexdump(&body[1..], ctx.base + 1, 6);
    }
}
