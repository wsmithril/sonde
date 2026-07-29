//! Manufacturer frames whose whole body is a bare 6-byte address.
//!
//! Several Company IDs carry nothing but a MAC-48 in display (MSB-first) order:
//! BandSpeed 0x0020, HM Electronics 0x034C, Typo Products 0x00FF, and the
//! unregistered 0x1200. Two of these advertise addresses under the same OUI as
//! each other, which is the sign of a chipset vendor's stock firmware reusing
//! whatever Company ID the SDK sample shipped with rather than of the named
//! company. The address is the payload, so it is printed with an IEEE OUI
//! lookup — a stable identifier even when the advertising address rotates.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Manufacturer frames that consist of a single 6-byte address.
pub(super) struct MacFrame;
impl super::VendorDecoder for MacFrame {
    fn company_ids(&self) -> &'static [u16] { &[0x0020, 0x034C, 0x00FF, 0x1200] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() != 6 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    bare-MAC frame (0x{:04X}): addr=", ctx.key);
        super::write_mac_be(&mut s, body);
        emit(s);
        super::emit_oui_vendor(body);
    }
}
