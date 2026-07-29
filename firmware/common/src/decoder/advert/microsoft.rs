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
        if body.is_empty() { return; }
        // Beacon ID 0x03 is Swift Pair — a different layout from the CDP
        // proximity beacon, carrying a plaintext display name (and, for BR/EDR
        // variants, a static MAC) rather than a device-identity hash.
        if body[0] == 0x03 {
            Self::swift_pair(ctx, body);
            return;
        }
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
    /// Swift Pair beacon (Beacon ID 0x03): sub-scenario, a reserved RSSI byte,
    /// then — for BR/EDR variants — a 6-byte static classic MAC (on-air LE),
    /// then a plaintext UTF-8 display name. The name is the exact string shown
    /// in the Windows pairing toast; no secret is needed to read it.
    fn swift_pair(_ctx: &super::DecodeCtx, body: &[u8]) {
        let sub = body.get(1).copied().unwrap_or(0);
        let subname = match sub { 0 => "LE", 1 => "BR/EDR", 2 => "dual", _ => "?" };
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    MS Swift Pair: pairing-over={}(0x{:02X})", subname, sub);
        // Bytes after the reserved RSSI byte: an optional static MAC prefix, then
        // the name. The name is the trailing printable run; anything binary
        // before it is the classic MAC (shown little-endian, high octet first).
        let rest = if body.len() > 3 { &body[3..] } else { &body[0..0] };
        let name_start = rest.iter()
            .position(|&b| b >= 0x20 && b != 0x7F)
            .unwrap_or(rest.len());
        if name_start >= 6 {
            let a = &rest[name_start - 6..name_start];
            let _ = write!(s, " mac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                a[5], a[4], a[3], a[2], a[1], a[0]);
        }
        let tail = &rest[name_start..];
        let end = tail.iter().rposition(|&b| b != 0x00).map_or(0, |p| p + 1);
        if let Ok(n) = core::str::from_utf8(&tail[..end])
            && !n.is_empty()
            && n.chars().all(|c| !c.is_control())
        {
            let _ = write!(s, " name=\"{}\"", n);
        }
        emit(s);
    }

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
