//! Microsoft CDP (Connected Devices Platform) beacon (Company ID 0x0006).
//!
//! Two protocols share this CID:
//!
//! * **Swift Pair** — Beacon ID (byte 0) `0x03`. Documented by Microsoft
//!   (learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/
//!   bluetooth-swift-pair): sub-scenario byte `0x00` LE-only, `0x01` BR/EDR-only
//!   via LE discovery, `0x02` LE + BR/EDR with SC; reserved RSSI byte `0x80`;
//!   then an optional 6-byte classic MAC and a plaintext display name.
//!
//! * **CDP proximity beacon** — Beacon ID (byte 0) is the scenario type.
//!   `0x01` = Bluetooth connectivity, `0x06` = Cloud messaging (Adwatch
//!   RE, github.com/bensmith83/adwatch/blob/main/docs/protocols/microsoft-cdp.md).
//!   Byte 1 packs the version (upper 3 bits) and the device type (lower 5 bits),
//!   e.g. `0x2F` → version 1, device type 15 (Windows Laptop). Byte 2+ is a
//!   scenario-specific salt/hash and stays as hex.
//!
//! Beacon IDs other than `0x03`/`0x01`/`0x06` (e.g. `0x47`, seen in newer Phone
//! Link / Nearby Sharing broadcasts) are printed unlabelled: no public
//! byte-level RE is available for them and guessing the device-type nibble
//! would fabricate identity fields.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Microsoft — manufacturer data (Company ID 0x0006): Swift Pair / CDP beacons.
pub(super) struct Microsoft;
impl super::VendorDecoder for Microsoft {
    fn company_ids(&self) -> &'static [u16] { &[0x0006] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        match body[0] {
            0x03 => Self::swift_pair(ctx, body),
            // Adwatch-documented CDP scenarios: byte 1 = (version:3)(device:5).
            0x01 | 0x06 => Self::cdp_known(ctx, body),
            // Other Beacon IDs (e.g. 0x47 seen with Phone Link / Nearby
            // Sharing) have no public byte layout — label and dump.
            _ => Self::cdp_unknown(ctx, body),
        }
    }
}

impl Microsoft {
    fn cdp_known(ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 3 { return; }
        let scenario = body[0];
        let dev      = body[1] & 0x1F;   // lower 5 bits = device type
        let ver      = (body[1] >> 5) & 0x07; // upper 3 bits = version
        let flags    = body[2];

        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    MS CDP: scenario={} ({}) device={} (0x{:02X}) ver={} flags=0x{:02X}\r\n",
            scenario, Self::scenario_name(scenario), Self::device_type(dev), dev, ver, flags);
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

    /// Beacon IDs outside the documented Swift Pair / CDP set. The layout is
    /// unknown — no public RE was located — so only the ID and raw bytes are
    /// surfaced. Do not decode a device-type nibble here: it would guess at a
    /// field whose position and width we cannot confirm.
    fn cdp_unknown(ctx: &super::DecodeCtx, body: &[u8]) {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    MS CDP: beacon-id=0x{:02X} (unknown layout) len={}",
            body[0], body.len() - 1);
        emit(s);
        hexdump(&body[1..], ctx.base + 1, 6);
    }

    /// Swift Pair beacon (Beacon ID 0x03): sub-scenario, a reserved RSSI byte
    /// (`0x80`), then — for BR/EDR variants — a 6-byte static classic MAC (on-air
    /// LE), then a plaintext UTF-8 display name. The name is the exact string
    /// shown in the Windows pairing toast; no secret is needed to read it.
    fn swift_pair(_ctx: &super::DecodeCtx, body: &[u8]) {
        let sub = body.get(1).copied().unwrap_or(0);
        let subname = match sub {
            0x00 => "LE",
            0x01 => "BR/EDR via LE discovery",
            0x02 => "LE + BR/EDR SC",
            _ => "?",
        };
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

    /// CDP scenario name.
    fn scenario_name(s: u8) -> &'static str {
        match s {
            0x01 => "Bluetooth connectivity",
            0x06 => "Cloud messaging",
            _    => "?",
        }
    }

    /// CDP beacon device-type code → name (lower 5 bits of body[1]).
    fn device_type(t: u8) -> &'static str {
        match t {
            1  => "Xbox",
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
