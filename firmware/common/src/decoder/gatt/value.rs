//! GATT characteristic value decoding: a small set of well-known SIG values plus a
//! couple of vendor ones, each rendered to one readable line. Every decoder returns
//! the line and the number of leading bytes it consumed, so the caller hex-dumps
//! only whatever trails the decoded fields.

use core::fmt::Write;

use crate::decoder::LogStr;

/// Bluetooth "Day of Week" code (1 = Monday … 7 = Sunday, 0 = unknown) → label.
fn dow_name(d: u8) -> &'static str {
    match d {
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        6 => "Sat",
        7 => "Sun",
        _ => "?",
    }
}

/// A broken-down wall-clock decoded from a Current Time / Date Time value.
pub(crate) struct WallTime {
    pub(crate) year: u16,
    pub(crate) month: u8,
    pub(crate) day: u8,
    pub(crate) hour: u8,
    pub(crate) min: u8,
    pub(crate) sec: u8,
    /// Day-of-week code (0 = unknown, 1 = Monday … 7 = Sunday); 0 if absent.
    pub(crate) dow: u8,
    /// Current Time adjust-reason bitfield; 0 if absent.
    pub(crate) adj: u8,
    /// Unix epoch seconds for the fields above.
    pub(crate) epoch: u32,
}

/// Decode the 7-byte Date Time prefix shared by Current Time (0x2A2B), Exact
/// Time 256 (0x2A0C) and Date Time (0x2A08), plus the day-of-week / adjust-reason
/// bytes where present — but only when the value passes a plausibility gate (so a
/// garbage read never anchors a bogus clock). `None` for any other characteristic
/// or an implausible value.
pub(crate) fn decode_time(uuid16: u16, v: &[u8]) -> Option<WallTime> {
    if !matches!(uuid16, 0x2A2B | 0x2A0C | 0x2A08) || v.len() < 7 {
        return None;
    }
    let year = u16::from_le_bytes([v[0], v[1]]);
    let (month, day, hour, min, sec) = (v[2], v[3], v[4], v[5], v[6]);
    if !(2000..=2100).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour >= 24
        || min >= 60
        || sec >= 60
    {
        return None;
    }
    Some(WallTime {
        year,
        month,
        day,
        hour,
        min,
        sec,
        dow: if v.len() >= 8 { v[7] } else { 0 },
        // adjust_reason is the trailing byte of Current Time only (index 9).
        adj: if uuid16 == 0x2A2B && v.len() >= 10 { v[9] } else { 0 },
        epoch: crate::wallclock::to_epoch(year, month, day, hour, min, sec),
    })
}

/// Format a decoded [`WallTime`] as the one-line `walltime:` log fragment.
pub(crate) fn format_walltime(t: &WallTime, uuid16: u16, s: &mut LogStr) {
    let _ = write!(
        s,
        "        walltime: {:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z src=0x{:04X} dow={} adj=0x{:02X}",
        t.year, t.month, t.day, t.hour, t.min, t.sec, uuid16, dow_name(t.dow), t.adj
    );
}

/// Name for a high-prevalence USB Implementer's Forum vendor id, as carried by a
/// PnP ID (0x2A50) with source 0x02. USB VIDs are a registry separate from the SIG
/// Company Identifiers, so [`crate::decoder::company_name`] cannot name them; this
/// is a curated set of the consumer vendors that actually appear on BLE
/// peripherals. `None` for anything outside the set — the raw VID still prints.
fn usb_vid_name(vid: u16) -> Option<&'static str> {
    Some(match vid {
        0x05AC => "Apple",
        0x04E8 => "Samsung",
        0x18D1 => "Google",
        0x054C => "Sony",
        0x045E => "Microsoft",
        0x05A7 => "Bose",
        0x046D => "Logitech",
        0x1915 => "Nordic Semiconductor",
        0x091E => "Garmin",
        0x057E => "Nintendo",
        0x2717 => "Xiaomi",
        0x248A => "Telink Semiconductor",
        0x0A12 => "Cambridge Silicon Radio",
        0x0BDA => "Realtek",
        0x8087 => "Intel",
        0x22B8 => "Motorola",
        0x0BB4 => "HTC",
        0x1949 => "Amazon",
        _ => return None,
    })
}

/// Decode a small set of well-known SIG characteristic values into a readable
/// one-line form. `None` for anything not specifically handled (the caller then
/// dumps the whole value). Time characteristics are handled separately by
/// [`decode_time`].
pub(crate) fn known_value(uuid16: u16, v: &[u8]) -> Option<(LogStr, usize)> {
    let mut s = LogStr::new();
    let consumed = match uuid16 {
        // Device Name + Device Information Service strings: UTF-8, NUL-trimmed.
        0x2A00 | 0x2A24 | 0x2A25 | 0x2A26 | 0x2A27 | 0x2A28 | 0x2A29 => {
            let end = v.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
            let text = core::str::from_utf8(&v[..end]).ok()?;
            let _ = write!(s, "        = \"{}\"", text);
            v.len()
        }
        // Battery Level: one byte, percent.
        0x2A19 if !v.is_empty() => {
            let _ = write!(s, "        = {}%", v[0]);
            1
        }
        // Appearance: 16-bit GAP category.
        0x2A01 if v.len() >= 2 => {
            let a = u16::from_le_bytes([v[0], v[1]]);
            let _ = write!(s, "        = appearance 0x{:04X} ({})", a, crate::decoder::appearance_name(a));
            2
        }
        // Peripheral Preferred Connection Parameters: 4× u16 (interval unit
        // 1.25 ms, timeout unit 10 ms).
        0x2A04 if v.len() >= 8 => {
            let mn = u16::from_le_bytes([v[0], v[1]]) as u32 * 5 / 4;
            let mx = u16::from_le_bytes([v[2], v[3]]) as u32 * 5 / 4;
            let lat = u16::from_le_bytes([v[4], v[5]]);
            let to = u16::from_le_bytes([v[6], v[7]]) as u32 * 10;
            let _ = write!(s, "        = conn {}-{}ms latency={} timeout={}ms", mn, mx, lat, to);
            8
        }
        // PnP ID: source(1) + vendor(2) + product(2) + version(2).
        0x2A50 if v.len() >= 7 => {
            let src = v[0];
            let vid = u16::from_le_bytes([v[1], v[2]]);
            let pid = u16::from_le_bytes([v[3], v[4]]);
            let ver = u16::from_le_bytes([v[5], v[6]]);
            let _ = write!(s, "        = pnp src={} vid=0x{:04X}", src, vid);
            // src 0x01 = Bluetooth SIG Company ID; src 0x02 = USB-IF Vendor ID.
            let vendor = match src {
                0x01 => crate::decoder::company_name(vid),
                0x02 => usb_vid_name(vid),
                _ => None,
            };
            if let Some(name) = vendor {
                let _ = write!(s, " ({})", name);
            }
            let _ = write!(s, " pid=0x{:04X} ver=0x{:04X}", pid, ver);
            7
        }
        // System ID: 40-bit manufacturer id (v[0..5]) + 24-bit OUI (v[5..8]),
        // each least-significant octet first.
        0x2A23 if v.len() >= 8 => {
            let oui = (v[7] as u32) << 16 | (v[6] as u32) << 8 | v[5] as u32;
            let _ = write!(s, "        = systemid oui={:06X}", oui);
            if let Some(name) = crate::decoder::oui_vendor(oui, None) {
                let _ = write!(s, " ({})", name);
            }
            8
        }
        // Database Hash: 128-bit AES-CMAC over the peer's attribute table (GATT
        // caching, BLE 5.1+). Opaque, but a stable fingerprint of the GATT layout.
        0x2B2A if v.len() == 16 => {
            let _ = s.push_str("        = db-hash ");
            for b in v {
                let _ = write!(s, "{:02X}", b);
            }
            16
        }
        // Central Address Resolution: one byte, 0/1. 1 = the peer knows this
        // central resolves RPAs, so it may use a resolvable private address to us.
        0x2AA6 if !v.is_empty() => {
            let _ = write!(
                s, "        = addr-resolution {}",
                if v[0] == 1 { "supported" } else { "not-supported" }
            );
            1
        }
        // Server Supported Features: one byte. Only bit 0 is defined (EATT).
        0x2B3A if !v.is_empty() => {
            let _ = write!(
                s, "        = server-features{}",
                if v[0] & 0x01 != 0 { " EATT" } else { "" }
            );
            1
        }
        // Client Supported Features: one byte bitfield (Core Vol 3 Part G).
        0x2B29 if !v.is_empty() => {
            let f = v[0];
            let _ = s.push_str("        = client-features");
            if f & 0x01 != 0 { let _ = s.push_str(" robust-caching"); }
            if f & 0x02 != 0 { let _ = s.push_str(" EATT"); }
            if f & 0x04 != 0 { let _ = s.push_str(" multi-notify"); }
            if f == 0 { let _ = s.push_str(" none"); }
            1
        }
        _ => return None,
    };
    Some((s, consumed))
}

/// Android Information Service "API level" characteristic (E73E0002-…) in on-air
/// little-endian order, for matching against a discovered characteristic's UUID.
const AIS_API_LEVEL_CHAR_LE: [u8; 16] = [
    0xB5, 0xF3, 0x64, 0x31, 0x4F, 0x2E, 0x91, 0x82, 0x74, 0x4E, 0x1B, 0xEF, 0x02, 0x00, 0x3E, 0xE7,
];

/// Android marketing version for an API level (recent releases; older ones fall
/// back to the bare number). Mapping is public (AOSP `Build.VERSION_CODES`).
fn android_release(api: u32) -> Option<&'static str> {
    Some(match api {
        36 => "16",
        35 => "15",
        34 => "14",
        33 => "13",
        31 | 32 => "12",
        30 => "11",
        29 => "10",
        28 => "9",
        26 | 27 => "8",
        24 | 25 => "7",
        23 => "6",
        _ => return None,
    })
}

/// Decode a known 128-bit characteristic value. Currently the Android Information
/// Service API-level char (little-endian u32, e.g. 0x24000000 → 36 → Android 16).
/// `uuid_le` is the on-air (little-endian) characteristic UUID.
pub(crate) fn known_value_128(uuid_le: &[u8], v: &[u8]) -> Option<(LogStr, usize)> {
    if uuid_le == AIS_API_LEVEL_CHAR_LE && v.len() >= 4 {
        let api = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
        let mut s = LogStr::new();
        match android_release(api) {
            Some(r) => { let _ = write!(s, "        = Android API {} (Android {})", api, r); }
            None => { let _ = write!(s, "        = Android API {}", api); }
        }
        return Some((s, 4));
    }
    None
}
