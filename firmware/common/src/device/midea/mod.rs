//! Midea / Hualing appliances.
//!
//! Midea appliances advertise a 0x06A8 manufacturer frame carrying a serial
//! number (decoded in [`crate::decoder::advert`]) and, once connected, expose a
//! control channel over GATT service `0xFFA0` (write `0xFFA1`, notify `0xFFA2`).
//!
//! This module holds the connection-side logic: passive decode of the
//! control-channel framing ([`gatt`]), the three-layer transport builders
//! ([`frame`]), and the AC command/status codec ([`control`]). The crypto layer
//! (rootKey/sessionKey AES-CCM) can grow here as a further submodule. Only
//! [`gatt`] is wired in today; [`frame`]/[`control`] are the encode side, ready
//! but unused.

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
