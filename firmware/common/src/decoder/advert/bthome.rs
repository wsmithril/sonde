//! BTHome v2 service data (UUID 0xFCD2).
//!
//! An **open** advertising format (bthome.io) rather than a reverse-engineered
//! vendor one — Shelly ships it and the DIY ecosystem targets it, so unlike the
//! per-vendor decoders here it is specified and stable. The UUID was donated by
//! Allterco Robotics (Shelly), which is why it also appears on some of that
//! vendor's own frames; those are labelled and dumped rather than guessed at.
//!
//! Layout after the 16-bit UUID:
//!
//! ```text
//! [devinfo] [obj_id][value…] [obj_id][value…] …
//! ```
//!
//! * `devinfo` — bit0 encrypted, bit2 trigger-based (irregular interval),
//!   bits 5-7 version (`010` = v2).
//! * Each record is an object ID then a little-endian value whose width and
//!   scaling the ID fixes. IDs appear in ascending order and a reader must stop
//!   at the first unknown ID — that ordering rule is the format's
//!   forward-compatibility guarantee, so this decoder honours it rather than
//!   trying to resynchronise.
//!
//! Encrypted payloads (bit0) are AES-CCM under a pre-shared per-device key we do
//! not have, so they are reported and left as hex.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// How a record's bytes turn into a reading.
#[derive(Clone, Copy)]
enum Kind {
    /// Unsigned little-endian, rendered with `dec` decimal places.
    U(u8),
    /// Signed little-endian, rendered with `dec` decimal places.
    I(u8),
    /// One byte, 0/1 — rendered with the (off, on) labels.
    Bin(&'static str, &'static str),
}

/// `(object id, name, value width in bytes, kind, unit)`.
///
/// The sensor and binary-sensor tables from the BTHome v2 spec. Entries whose
/// factor is not a power of ten (0x58 temperature ×0.35) are deliberately absent:
/// a wrong scale reads as a plausible measurement, which is worse than stopping.
const OBJECTS: &[(u8, &str, u8, Kind, &str)] = &[
    // ── device info ──
    (0x00, "packet-id",      1, Kind::U(0), ""),
    // ── sensors ──
    (0x01, "battery",        1, Kind::U(0), "%"),
    (0x02, "temperature",    2, Kind::I(2), "C"),
    (0x03, "humidity",       2, Kind::U(2), "%"),
    (0x04, "pressure",       3, Kind::U(2), "hPa"),
    (0x05, "illuminance",    3, Kind::U(2), "lx"),
    (0x06, "mass",           2, Kind::U(2), "kg"),
    (0x07, "mass",           2, Kind::U(2), "lb"),
    (0x08, "dewpoint",       2, Kind::I(2), "C"),
    (0x09, "count",          1, Kind::U(0), ""),
    (0x0A, "energy",         3, Kind::U(3), "kWh"),
    (0x0B, "power",          3, Kind::U(2), "W"),
    (0x0C, "voltage",        2, Kind::U(3), "V"),
    (0x0D, "pm2.5",          2, Kind::U(0), "ug/m3"),
    (0x0E, "pm10",           2, Kind::U(0), "ug/m3"),
    (0x12, "co2",            2, Kind::U(0), "ppm"),
    (0x13, "tvoc",           2, Kind::U(0), "ug/m3"),
    (0x14, "moisture",       2, Kind::U(2), "%"),
    (0x2E, "humidity",       1, Kind::U(0), "%"),
    (0x2F, "moisture",       1, Kind::U(0), "%"),
    (0x3D, "count",          2, Kind::U(0), ""),
    (0x3E, "count",          4, Kind::U(0), ""),
    (0x3F, "rotation",       2, Kind::I(1), "deg"),
    (0x40, "distance",       2, Kind::U(0), "mm"),
    (0x41, "distance",       2, Kind::U(1), "m"),
    (0x42, "duration",       3, Kind::U(3), "s"),
    (0x43, "current",        2, Kind::U(3), "A"),
    (0x44, "speed",          2, Kind::U(2), "m/s"),
    (0x45, "temperature",    2, Kind::I(1), "C"),
    (0x46, "uv-index",       1, Kind::U(1), ""),
    (0x47, "volume",         2, Kind::U(1), "L"),
    (0x48, "volume",         2, Kind::U(0), "mL"),
    (0x49, "volume-flow",    2, Kind::U(3), "m3/hr"),
    (0x4A, "voltage",        2, Kind::U(1), "V"),
    (0x4B, "gas",            3, Kind::U(3), "m3"),
    (0x4C, "gas",            4, Kind::U(3), "m3"),
    (0x4D, "energy",         4, Kind::U(3), "kWh"),
    (0x4E, "volume",         4, Kind::U(3), "L"),
    (0x4F, "water",          4, Kind::U(3), "L"),
    (0x50, "timestamp",      4, Kind::U(0), "epoch"),
    (0x51, "acceleration",   2, Kind::U(3), "m/s2"),
    (0x52, "gyroscope",      2, Kind::U(3), "deg/s"),
    (0x55, "volume-storage", 4, Kind::U(3), "L"),
    (0x56, "conductivity",   2, Kind::U(0), "uS/cm"),
    (0x57, "temperature",    1, Kind::I(0), "C"),
    (0x59, "count",          1, Kind::I(0), ""),
    (0x5A, "count",          2, Kind::I(0), ""),
    (0x5B, "count",          4, Kind::I(0), ""),
    (0x5C, "power",          4, Kind::I(2), "W"),
    (0x5D, "current",        2, Kind::I(3), "A"),
    (0x5E, "direction",      2, Kind::U(2), "deg"),
    (0x5F, "precipitation",  2, Kind::U(1), "mm"),
    (0x60, "channel",        1, Kind::U(0), ""),
    (0x61, "rpm",            2, Kind::U(0), "rpm"),
    (0x64, "light-level",    1, Kind::U(0), ""),
    (0x65, "settings-rev",   1, Kind::U(0), ""),
    // ── binary sensors (1 byte, 0/1) ──
    (0x0F, "generic",     1, Kind::Bin("off", "on"), ""),
    (0x10, "power",       1, Kind::Bin("off", "on"), ""),
    (0x11, "opening",     1, Kind::Bin("closed", "open"), ""),
    (0x15, "battery",     1, Kind::Bin("ok", "low"), ""),
    (0x16, "charging",    1, Kind::Bin("no", "yes"), ""),
    (0x17, "co",          1, Kind::Bin("clear", "detected"), ""),
    (0x18, "cold",        1, Kind::Bin("normal", "cold"), ""),
    (0x19, "connectivity",1, Kind::Bin("down", "up"), ""),
    (0x1A, "door",        1, Kind::Bin("closed", "open"), ""),
    (0x1B, "garage-door", 1, Kind::Bin("closed", "open"), ""),
    (0x1C, "gas",         1, Kind::Bin("clear", "detected"), ""),
    (0x1D, "heat",        1, Kind::Bin("normal", "hot"), ""),
    (0x1E, "light",       1, Kind::Bin("dark", "light"), ""),
    (0x1F, "lock",        1, Kind::Bin("locked", "unlocked"), ""),
    (0x20, "moisture",    1, Kind::Bin("dry", "wet"), ""),
    (0x21, "motion",      1, Kind::Bin("clear", "detected"), ""),
    (0x22, "moving",      1, Kind::Bin("no", "yes"), ""),
    (0x23, "occupancy",   1, Kind::Bin("clear", "detected"), ""),
    (0x24, "plug",        1, Kind::Bin("unplugged", "plugged"), ""),
    (0x25, "presence",    1, Kind::Bin("away", "home"), ""),
    (0x26, "problem",     1, Kind::Bin("ok", "problem"), ""),
    (0x27, "running",     1, Kind::Bin("no", "yes"), ""),
    (0x28, "safety",      1, Kind::Bin("unsafe", "safe"), ""),
    (0x29, "smoke",       1, Kind::Bin("clear", "detected"), ""),
    (0x2A, "sound",       1, Kind::Bin("clear", "detected"), ""),
    (0x2B, "tamper",      1, Kind::Bin("off", "tampered"), ""),
    (0x2C, "vibration",   1, Kind::Bin("clear", "detected"), ""),
    (0x2D, "window",      1, Kind::Bin("closed", "open"), ""),
];

fn lookup(id: u8) -> Option<&'static (u8, &'static str, u8, Kind, &'static str)> {
    OBJECTS.iter().find(|o| o.0 == id)
}

/// BTHome v2 — service data (UUID 0xFCD2).
pub(super) struct BtHome;
impl super::VendorDecoder for BtHome {
    fn service_uuids(&self) -> &'static [u16] { &[0xFCD2] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        let Some(&devinfo) = body.first() else { return };
        let version = devinfo >> 5;
        let encrypted = devinfo & 0x01 != 0;
        let trigger = (devinfo >> 2) & 0x01 != 0;

        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    BTHome v{}", version);
        if trigger { let _ = write!(s, " trigger"); }

        // Only v2 is specified here. An older//newer frame — or one of Allterco's
        // own non-BTHome frames on the same donated UUID — is named and dumped
        // rather than parsed with the wrong table.
        if version != 2 {
            let _ = write!(s, " (not v2 — not decoded) len={}", body.len());
            emit(s);
            hexdump(body, ctx.base, 6);
            return;
        }
        if encrypted {
            let _ = write!(s, " encrypted (AES-CCM, key not held) len={}", body.len());
            emit(s);
            hexdump(&body[1..], ctx.base + 1, 6);
            return;
        }
        emit(s);

        let mut i = 1;
        while i < body.len() {
            let id = body[i];
            i += 1;
            // Text (0x53) and raw (0x54) are length-prefixed rather than fixed width.
            if id == 0x53 || id == 0x54 {
                let Some(&n) = body.get(i) else { return };
                i += 1;
                let end = (i + n as usize).min(body.len());
                let mut t: LogStr = LogStr::new();
                if id == 0x53 {
                    let _ = write!(t, "      text=\"");
                    for &b in &body[i..end] {
                        let _ = t.push(if (0x20..=0x7E).contains(&b) { b as char } else { '.' });
                    }
                    let _ = write!(t, "\"");
                } else {
                    let _ = write!(t, "      raw=");
                    for &b in &body[i..end] { let _ = write!(t, "{:02X}", b); }
                }
                emit(t);
                i = end;
                continue;
            }
            // Events carry their own small shapes.
            if id == 0x3A || id == 0x3B || id == 0x3C {
                i = Self::event(id, body, i);
                continue;
            }
            let Some(obj) = lookup(id) else {
                // Unknown ID: per spec the remainder cannot be located, so stop.
                let mut u: LogStr = LogStr::new();
                let _ = write!(u, "      obj 0x{:02X} unknown — stopping ({}B left)", id, body.len() - i);
                emit(u);
                hexdump(&body[i..], ctx.base + i, 6);
                return;
            };
            let (_, name, len, kind, unit) = *obj;
            let end = i + len as usize;
            if end > body.len() { return; }
            let raw = &body[i..end];
            i = end;

            let mut v: LogStr = LogStr::new();
            match kind {
                Kind::Bin(off, on) => {
                    let _ = write!(v, "      {}={}", name, if raw[0] != 0 { on } else { off });
                }
                Kind::U(dec) => {
                    let mut n: u64 = 0;
                    for (k, &b) in raw.iter().enumerate() { n |= (b as u64) << (8 * k); }
                    let _ = write!(v, "      {}=", name);
                    write_scaled(&mut v, n as i64, dec);
                    if !unit.is_empty() { let _ = write!(v, "{}", unit); }
                }
                Kind::I(dec) => {
                    let _ = write!(v, "      {}=", name);
                    write_scaled(&mut v, le_signed(raw), dec);
                    if !unit.is_empty() { let _ = write!(v, "{}", unit); }
                }
            }
            emit(v);
        }
    }
}

impl BtHome {
    /// Button / command / dimmer events. Returns the new cursor.
    fn event(id: u8, body: &[u8], mut i: usize) -> usize {
        let mut s: LogStr = LogStr::new();
        match id {
            0x3A => {
                let e = body.get(i).copied().unwrap_or(0);
                i += 1;
                let n = match e {
                    0x00 => "none", 0x01 => "press", 0x02 => "double", 0x03 => "triple",
                    0x04 => "long", 0x05 => "long-double", 0x06 => "long-triple",
                    0x80 => "hold", _ => "?",
                };
                let _ = write!(s, "      button={}", n);
            }
            0x3C => {
                let e = body.get(i).copied().unwrap_or(0);
                let steps = body.get(i + 1).copied().unwrap_or(0);
                i += 2;
                let n = match e { 0x00 => "none", 0x01 => "rotate-left", 0x02 => "rotate-right", _ => "?" };
                let _ = write!(s, "      dimmer={} steps={}", n, steps);
            }
            _ => {
                // 0x3B command: [arglen (low 5 bits)][opcode][args…]
                let alen = (body.get(i).copied().unwrap_or(0) & 0x1F) as usize;
                i += 1;
                let op = body.get(i).copied().unwrap_or(0);
                i += 1;
                let n = match op {
                    0x00 => "off", 0x01 => "on", 0x02 => "toggle",
                    0x03 => "step-up", 0x04 => "step-down", _ => "?",
                };
                let _ = write!(s, "      command={}", n);
                if alen > 0 {
                    let end = (i + alen - 1).min(body.len());
                    let _ = write!(s, " args=");
                    for &b in &body[i.min(body.len())..end] { let _ = write!(s, "{:02X}", b); }
                    i = end;
                }
            }
        }
        emit(s);
        i
    }
}

/// Little-endian bytes to a sign-extended integer of the field's own width.
///
/// Split out so the sign extension — the one piece of arithmetic here that fails
/// silently and plausibly (a negative temperature reads as a huge positive one) —
/// can be pinned at compile time below.
const fn le_signed(raw: &[u8]) -> i64 {
    let mut n: u64 = 0;
    let mut k = 0;
    while k < raw.len() {
        n |= (raw[k] as u64) << (8 * k);
        k += 1;
    }
    let bits = 8 * raw.len() as u32;
    if n & (1 << (bits - 1)) != 0 {
        (n as i64) - (1i64 << bits)
    } else {
        n as i64
    }
}

/// The spec's own worked example plus the sign boundary, checked at build time —
/// the same treatment `hal::csa2` gives its Core-spec vectors. `02 C4 09` is the
/// documented 25.00 °C sample (sint16 2500 × 0.01); the rest pin sign extension
/// at each width, where an off-by-one turns −1 °C into 655.35 °C.
const _: () = {
    assert!(le_signed(&[0xC4, 0x09]) == 2500); // spec: 25.00 C
    assert!(le_signed(&[0xFF, 0xFF]) == -1);
    assert!(le_signed(&[0x00, 0x80]) == -32768);
    assert!(le_signed(&[0xFF, 0x7F]) == 32767);
    assert!(le_signed(&[0xFF]) == -1);
    assert!(le_signed(&[0x7F]) == 127);
    assert!(le_signed(&[0xFF, 0xFF, 0xFF, 0xFF]) == -1);
};

/// Render `v` scaled by `10^-dec` without floating point: integer part, then the
/// fractional digits the factor implies.
fn write_scaled(s: &mut LogStr, v: i64, dec: u8) {
    if dec == 0 {
        let _ = write!(s, "{}", v);
        return;
    }
    let div = 10i64.pow(dec as u32);
    let neg = v < 0;
    let a = if neg { -v } else { v };
    if neg { let _ = write!(s, "-"); }
    let _ = write!(s, "{}.{:0width$}", a / div, a % div, width = dec as usize);
}
