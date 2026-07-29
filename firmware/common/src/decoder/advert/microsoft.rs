//! Microsoft CDP (Connected Devices Platform) beacon (Company ID 0x0006).
//!
//! The header carries a scenario, a device type, and a version; the tail is a
//! salt plus an opaque device-identity hash that stays as hex.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Microsoft — manufacturer data (Company ID 0x0006): Swift Pair / CDP beacons.
pub(super) struct Microsoft;
impl super::VendorDecoder for Microsoft {
    fn company_ids(&self) -> &'static [u16] { &[0x0006] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 3 { return; }
        let scenario = body[0];
        let dev      = body[1] & 0x3F; // lower 6 bits = device type
        let ver      = body[1] >> 6;
        let flags    = body[2];

        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    MS CDP: scenario={} device={} (0x{:02X}) ver={} flags=0x{:02X}\r\n",
            scenario, Self::device_type(dev), dev, ver, flags);
        emit(s);

        if body.len() >= 7 {
            let mut s2: LogStr = LogStr::new();
            let _ = write!(s2, "    MS CDP: salt=");
            write_hex(&mut s2, &body[3..7]);
            let _ = write!(s2, " hash(opaque) len={}", body.len() - 7);
            emit(s2);
            hexdump(&body[7..], ctx.base + 7, 6);
        }
    }
}

impl Microsoft {
    /// CDP beacon device-type code → name.
    fn device_type(t: u8) -> &'static str {
        match t {
            1  => "Xbox One",
            6  => "iPhone",
            7  => "iPad",
            8  => "Android",
            9  => "Windows Desktop",
            11 => "Windows Phone",
            12 => "Linux",
            13 => "Windows IoT",
            14 => "Surface Hub",
            15 => "Windows Laptop",
            16 => "Windows Tablet",
            _  => "?",
        }
    }
}
