//! Midea / Hualing appliances.
//!
//! Midea appliances advertise a 0x06A8 manufacturer frame carrying a serial
//! number (decoded in [`crate::decoder::advert`]) and, once connected, expose a
//! control channel over GATT service `0xFFA0` (write `0xFFA1`, notify `0xFFA2`).
//!
//! This module holds the Midea-specific logic: advert-serial detection
//! ([`parse_midea_sn`] / [`sn_matches`]), the device-type code from the serial
//! ([`device_type`]), the control-channel framing ([`gatt`]), the three-layer
//! transport builders ([`frame`]), the C1→C2→C3 handshake state machine
//! ([`handshake`]), and the AC command/status codec ([`control`], whose
//! `parse_status_frame` is the source of truth for the 0xC0 status decode).
//! The connection-driving probe that moves these over ATT lives in
//! `crate::mode::recon::midea`.

pub mod control;
pub mod crypto;
pub mod frame;
pub mod gatt;
pub mod handshake;
pub mod rng;
pub mod status;

/// The M-Smart device-type code embedded in the 14-char serial at `sn[8..10]`,
/// mapped to an appliance name. The serial is `SN8 + TT + UUUU`: the first 8
/// chars feed the rootKey, the next two are the M-Smart device-type byte written
/// as ASCII hex (`AC` = 0xAC air-conditioner, `FC` = air-purifier, …), the last
/// four are a unit suffix. Codes from the wuwentao/midea_ac_lan device table.
pub fn device_type(sn: &[u8; 14]) -> &'static str {
    match &sn[8..10] {
        b"AC" => "air-conditioner",
        b"FC" => "air-purifier",
        b"A1" => "dehumidifier",
        b"FA" => "fan",
        b"FB" => "electric-heater",
        b"FD" => "humidifier",
        b"CE" => "fresh-air",
        b"CD" => "heat-pump-water-heater",
        b"CF" => "heat-pump",
        b"E2" => "electric-water-heater",
        b"E3" => "gas-water-heater",
        b"E6" => "gas-stove",
        b"E1" => "dishwasher",
        b"EA" => "rice-cooker",
        b"EC" => "pressure-cooker",
        b"ED" => "water-dispenser",
        b"DA" => "top-load-washer",
        b"DB" => "front-load-washer",
        b"DC" => "clothes-dryer",
        b"CA" => "refrigerator",
        b"B6" => "range-hood",
        b"BF" => "microwave-steam-oven",
        b"B0" => "microwave-oven",
        b"B1" => "electric-oven",
        b"AD" => "air-box",
        b"13" => "light",
        _ => "unknown",
    }
}

/// Whether the serial carries a recognised M-Smart device-type code — the gate
/// for the control mode to attempt a handshake rather than log-and-skip.
pub fn is_known_type(sn: &[u8; 14]) -> bool {
    device_type(sn) != "unknown"
}

/// Services the Midea-BLE protocol actually uses — the targeted walk set for
/// on-the-go mode. FFA0 = Midea control (FFA1 write + FFA2 notify), FF90 = second
/// Midea family present on some models, 0x180A = Device Information (model / FW
/// version), 0x1800 = GAP (device name). Matches what midea-ble-go probes.
pub fn is_service(uuid: Option<u16>) -> bool {
    matches!(uuid, Some(0xFFA0 | 0xFF90 | 0x180A | 0x1800))
}

/// Walk the AD structures of an advertising payload (the bytes after AdvA) and
/// return the 14-byte Midea short serial from a `[06 A8][01][SN14]` manufacturer
/// frame, if present.
pub fn parse_midea_sn(ad: &[u8]) -> Option<[u8; 14]> {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        let atype = ad[i + 1];
        let data = &ad[i + 2..i + 1 + flen];
        // Manufacturer data, company 0x06A8 (little-endian A8 06), frame type 0x01.
        if atype == 0xFF && data.len() >= 3 + 14 && data[0] == 0xA8 && data[1] == 0x06 && data[2] == 0x01 {
            let mut sn = [0u8; 14];
            sn.copy_from_slice(&data[3..3 + 14]);
            return Some(sn);
        }
        i += 1 + flen;
    }
    None
}

/// Whether a parsed serial is well-formed (printable ASCII) — a corrupt SN from
/// a bit-flipped advert is not a target.
pub fn sn_matches(sn: &[u8; 14]) -> bool {
    sn.iter().all(|&b| b.is_ascii_graphic())
}
