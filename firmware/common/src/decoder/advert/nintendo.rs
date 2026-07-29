//! Nintendo manufacturer data (Company ID 0x0553).
//!
//! Nintendo Switch 2 controllers beacon a fixed-layout frame to reconnect to, or
//! wake, their last-paired console. Layout (offsets after the company ID) per
//! ndeadly/switch2_controller_research `bluetooth_interface.md`, cross-checked
//! against a captured CONNECT_IND whose InitA matched the embedded host address:
//!
//! ```text
//! 01 00 03 | VV VV | PP PP | 00 01 | ST | host×6 (reversed) | 0F | 00×7
//!  prefix    vendor  product         state  paired console
//!            0x057E  controller type 0x81=wake / 0x00=reconnect
//! ```
//!
//! Controller type is the USB product ID (there is no separate type byte, and no
//! colour in the advert). Original-Switch Joy-Con/Pro use Bluetooth Classic and
//! do not emit this BLE frame; Switch 2 product IDs start at 0x2060.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Byte offset (after the company ID) of the reversed reconnect-host address.
const HOST_ADDR_OFF: usize = 10;

/// Nintendo Co., Ltd. — manufacturer data (Company ID 0x0553).
pub(super) struct Nintendo;
impl super::VendorDecoder for Nintendo {
    fn company_ids(&self) -> &'static [u16] { &[0x0553] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Nintendo:");

        // Recognised Switch-2 reconnect/wake frame: fixed prefix 01 00 03 and
        // vendor 0x057E (little-endian 7E 05).
        if body.len() >= HOST_ADDR_OFF + 6
            && body[0] == 0x01 && body[1] == 0x00 && body[2] == 0x03
            && body[3] == 0x7E && body[4] == 0x05
        {
            let pid = u16::from_le_bytes([body[5], body[6]]);
            let _ = write!(s, " {} (pid=0x{:04X})", Self::controller_name(pid), pid);
            let _ = write!(s, " {}", match body[9] {
                0x81 => "wake-console",
                0x00 => "reconnect",
                _ => "state?",
            });
            let a = &body[HOST_ADDR_OFF..HOST_ADDR_OFF + 6];
            let _ = write!(s, " host={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                a[5], a[4], a[3], a[2], a[1], a[0]);
            emit(s);
            // The remainder is the fixed 0x0F marker + reserved zeros — nothing to show.
            return;
        }

        // Unrecognised layout: surface the likely host address and dump the rest.
        let _ = write!(s, " len={}", body.len());
        if body.len() >= HOST_ADDR_OFF + 6 {
            let a = &body[HOST_ADDR_OFF..HOST_ADDR_OFF + 6];
            let _ = write!(s, " host≈{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                a[5], a[4], a[3], a[2], a[1], a[0]);
        }
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}

impl Nintendo {
    /// Controller type from the USB product ID. Original-Switch IDs are from
    /// `ndeadly/MissionControl` (`switch_controller.hpp`); Switch 2 uses IDs from
    /// 0x2060 up, whose per-model mapping is not yet publicly enumerated.
    fn controller_name(pid: u16) -> &'static str {
        match pid {
            0x2006 => "Joy-Con (L)",
            0x2007 => "Joy-Con (R)",
            0x2009 => "Pro Controller",
            0x2017 => "SNES Controller",
            0x2019 => "N64 Controller",
            0x201A => "Genesis/Mega Drive",
            _ if pid >= 0x2060 => "Switch 2 controller",
            _ => "?",
        }
    }
}
