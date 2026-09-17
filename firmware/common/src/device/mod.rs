//! Per-device protocol logic.
//!
//! Where a decoder module under [`crate::decoder`] recognises a vendor frame and
//! extracts fields, a `device` submodule goes deeper into one product family —
//! its GATT control channel, framing, crypto and command set — the parts that a
//! generic advertising/GATT decoder does not cover.
//!
//! [`classify_interest`] is the single entry point for device-of-interest
//! detection from an advertising payload, dispatching to the per-family
//! detectors.

use crate::central::Interest;

pub mod airoha;
pub mod daikin;
pub mod dessmann;
pub mod fanlight;
pub mod haier;
pub mod hisense;
pub mod jomoo;
pub mod mi;
pub mod midea;
pub mod portasplit;
pub mod utech;

/// Single entry point for device-of-interest detection from an advertising
/// payload: Midea (0x06A8 serial), DESSMANN lock (name `LOCK_`), MiBeacon
/// sensor, or weight scale (UUID16 0x181D). A generic advertiser returns `None`
/// — counted by the scan but never connected to.
///
/// A Midea advert whose serial fails [`midea::sn_matches`] (a bit-flipped field)
/// is not a target; the offending serial is reported through `bad_sn` so the scan
/// can log it once.
#[allow(dead_code)]
pub(crate) fn classify_interest(ad: &[u8], bad_sn: &mut Option<[u8; 14]>) -> Option<Interest> {
    if let Some(sn) = midea::parse_midea_sn(ad) {
        if midea::sn_matches(&sn) {
            return Some(Interest::Midea {
                sn,
                mac: midea::parse_midea_mac(ad),
            });
        }
        *bad_sn = Some(sn);
        return None;
    }
    // PortaSplit is a separate family (different advert layout) — checked on its
    // own, not as a Midea variant.
    if let Some(mat) = portasplit::material_of_ad(ad) {
        return Some(Interest::PortaSplit(mat));
    }
    // Fan-and-light: another separate family (0x06A8 `81 63 01` state advert).
    if let Some(st) = fanlight::state_of_ad(ad) {
        return Some(Interest::FanLight(st));
    }
    // Haier U-home appliance (mfg 0x0929) — probed by GATT walk.
    if haier::is_haier_advert(ad) {
        return Some(Interest::Haier);
    }
    // Hisense smart-life appliance (ServiceData16 0xF005) — BLE control via the
    // `3a69…` GATT profile.
    if hisense::is_hisense_advert(ad) {
        return Some(Interest::Hisense);
    }
    // JOMOO smart bathroom (name `JOMOO…`) — Telink 0xFFF0 control profile.
    if jomoo::is_jomoo_advert(ad) {
        return Some(Interest::Jomoo);
    }
    if dessmann::is_dessmann_advert(ad) {
        return Some(Interest::Dessmann);
    }
    if utech::is_utech_advert(ad) {
        return Some(Interest::Utech);
    }
    if mi::is_sensor_advert(ad) {
        return Some(Interest::MiSensor);
    }
    if mi::is_scale_advert(ad) {
        return Some(Interest::MiScale);
    }
    None
}

/// Extract a 16-bit UUID from a 2-byte or Bluetooth-base 16-byte ATT UUID.
pub(crate) fn uuid16(u: &[u8]) -> Option<u16> {
    if u.len() == 2 {
        return Some(u16::from_le_bytes([u[0], u[1]]));
    }
    if u.len() == 16 && u[..12] == BASE_UUID_PREFIX_LE && u[14] == 0 && u[15] == 0 {
        return Some(u16::from_le_bytes([u[12], u[13]]));
    }
    None
}

/// The Bluetooth Base UUID prefix (on-air LE) — identifies 16-bit UUIDs widened to
/// the full 128-bit form. Bytes [12..14] carry the 16-bit value; [14..16] are zero.
const BASE_UUID_PREFIX_LE: [u8; 12] = [
    0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00,
];
