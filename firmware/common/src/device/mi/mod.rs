//! Xiaomi "Mi" appliance family: the body-composition scale (Newbit `MI_Scale`
//! clone) and the MiBeacon sensors.
//!
//! **Scale** — broadcasts a measurement in its advertisement and, on connection,
//! exposes a vendor service `E7810B92-73AE-499D-8C15-FAA9AEF0C3F2` with a config
//! char `BEF8E7E0` (read/write) and a measurement notify char `BEF8E7E1`.
//!
//! Measurement packet (13 bytes, both in the advert and on the notify channel):
//! ```text
//!   [ctrl0][ctrl1][YY MM DD hh mm ss][impedance LE(2)][weight LE(2)]
//! ```
//! * ctrl0: bit 0 = unit (0 = kg, 1 = lbs), bit 3 = impedance present.
//! * datetime: six raw bytes (year, month, day, hour, minute, second).
//! * weight = raw / 200 kg (documented scale for the composition scale).
//!
//! The connection sequence (from the RE community: openScale, smartscale_reader)
//! is a 5-step: set units → set time → enable notify → configure user → request
//! measurement. The exact config-frame bytes for the Newbit clone are
//! HARDWARE-UNVERIFIED; the measurement parse itself follows the documented
//! format.
//!
//! Body composition (fat %, water, muscle, bone, visceral fat, BMI, BMR) is
//! computed from weight + impedance + user parameters via the Xiaomi/Holtek
//! calibrated formulas (see openScale `BodyMiScaleLib`) — not carried in the
//! packet; the packet carries weight + impedance + the measurement timestamp.
#![allow(dead_code)]

use heapless::Vec;

/// The scale's config (write) + measurement (notify) characteristics.
#[derive(Clone, Copy)]
pub struct Profile {
    pub config_h: u16,
    pub notify_h: u16,
}

/// A decoded 13-byte measurement packet.
#[derive(Clone, Copy)]
pub struct Measurement {
    /// Unit: `true` = lbs, `false` = kg.
    pub lbs: bool,
    /// Impedance present in the packet.
    pub has_impedance: bool,
    pub year: u8,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    /// Bio-impedance (raw ohms), when present.
    pub impedance: u16,
    /// Weight in the packet's unit (kg or lbs), before the /200 scale.
    pub raw_weight: u16,
}

impl Measurement {
    /// Weight in kg (raw / 200 for kg mode; lbs mode converts via 0.4536).
    pub fn weight_kg(&self) -> f32 {
        let v = self.raw_weight as f32 / 200.0;
        if self.lbs { v * 0.4536 } else { v }
    }
}

/// Parse a 13-byte measurement packet. Returns `None` if the length is wrong or
/// the weight field is implausible (0 or > 60,000).
pub fn parse_measurement(f: &[u8]) -> Option<Measurement> {
    if f.len() != 13 {
        return None;
    }
    let lbs = f[0] & 0x01 != 0;
    let has_impedance = f[0] & 0x08 != 0;
    let raw_weight = u16::from_le_bytes([f[11], f[12]]);
    if raw_weight == 0 || raw_weight > 60_000 {
        return None;
    }
    Some(Measurement {
        lbs,
        has_impedance,
        year: f[2],
        month: f[3],
        day: f[4],
        hour: f[5],
        minute: f[6],
        second: f[7],
        impedance: u16::from_le_bytes([f[9], f[10]]),
        raw_weight,
    })
}

/// Build the "set current time" config frame. The exact Newbit byte layout is
/// HARDWARE-UNVERIFIED — the format follows the documented Mi Scale convention
/// of a config write carrying the timestamp.
pub fn build_set_time(now_epoch: u32) -> Vec<u8, 20> {
    let mut f: Vec<u8, 20> = Vec::new();
    // Placeholder layout: the scale expects its own time struct. Keep it
    // minimal and flag it — the probe logs the scale's reaction to confirm.
    let _ = f.extend_from_slice(&now_epoch.to_le_bytes());
    f
}

/// Is this the Mi Scale vendor service (the config + notify channel)?
pub fn is_scale_service(svc_uuid: &[u8]) -> bool {
    svc_uuid == E7810B92_SERVICE
}

/// Detect a MiBeacon *sensor* advert (ServiceData16 UUID 0xFE95) for a known
/// sensor product: 0x0E39 (XMZNMS08LM door/window sensor 2) or 0x055B
/// (LYWSD03MMC temp/humidity monitor 2). The scan turns these into probe
/// candidates so recon can connect and read their sensor values (the stock
/// LYWSD03MMC exposes temp/humidity/battery via the GATT walk).
pub fn is_sensor_advert(ad: &[u8]) -> bool {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        if ad[i + 1] == 0x16 && flen >= 6 {
            // ServiceData16: [len][0x16][uuid FE95 LE][frame: fc(2) product(2)…]
            if ad[i + 2] == 0x95 && ad[i + 3] == 0xFE {
                let product = u16::from_le_bytes([ad[i + 6], ad[i + 7]]);
                if matches!(product, 0x0E39 | 0x055B) {
                    return true;
                }
            }
        }
        i += 1 + flen;
    }
    false
}

const E7810B92_SERVICE: [u8; 16] = [
    0xF2, 0xC3, 0xF0, 0xAE, 0xA9, 0xFA, 0x15, 0x8C, 0x9D, 0x49, 0xAE, 0x73, 0x92, 0x0B, 0x81, 0xE7,
];
const BEF8E7E0_CONFIG: [u8; 16] = [
    0x9F, 0x9F, 0x00, 0xC1, 0x58, 0xBD, 0x32, 0xB6, 0x9E, 0x4C, 0x21, 0x9C, 0xE0, 0xE7, 0xF8, 0xBE,
];
const BEF8E7E1_NOTIFY: [u8; 16] = [
    0x9F, 0x9F, 0x00, 0xC1, 0x58, 0xBD, 0x32, 0xB6, 0x9E, 0x4C, 0x21, 0x9C, 0xE1, 0xE7, 0xF8, 0xBE,
];

/// The scale service role of a characteristic UUID: config (write) or notify.
pub fn char_role(uuid: &[u8]) -> Option<Role> {
    if uuid == BEF8E7E0_CONFIG {
        Some(Role::Config)
    } else if uuid == BEF8E7E1_NOTIFY {
        Some(Role::Notify)
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Config,
    Notify,
}
