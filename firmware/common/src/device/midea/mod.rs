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
//! ([`handshake`]), and the per-appliance codecs under [`appliance`] (the AC
//! codec — `appliance::air_conditioner::parse_status_frame` — is the source of
//! truth for the 0xC0 status decode). The connection-driving probe that moves
//! these over ATT lives in `crate::mode::recon::midea`.

pub mod appliance;
pub mod crypto;
pub mod frame;
pub mod gatt;
pub mod handshake;
pub mod rng;
pub mod status;

// Backward-compatible path for the AC codec (now under `appliance/air_conditioner`):
// `device::midea::control::parse_status_frame` still resolves.
pub use appliance::air_conditioner as control;

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

/// The no-bind (FFA0 digital-control) SN8 whitelist, from the Midea cloud's
/// `getIotCodes` endpoint (config mode "17"). These are the SN8 prefixes the
/// app routes to the FFA0 control flow without a bind. Obtained 2026-09-01;
/// `is_ble_controller` in the advert is *not* a substitute — water heaters
/// advertise it yet are absent from this list.
pub const NO_BIND_SN8: [&[u8; 8]; 37] = [
    b"222L9993",
    b"220Z1807",
    b"220F4017",
    b"220F4009",
    b"22040035",
    b"220Z1808",
    b"2204002A",
    b"22040045",
    b"22040041",
    b"22040037",
    b"22040039",
    b"2204002B",
    b"222G5019",
    b"22040057",
    b"22040049",
    b"22040055",
    b"22040075",
    b"22040047",
    b"22040051",
    b"22040053",
    b"22270069",
    b"22270039",
    b"22270045",
    b"22270055",
    b"22270051",
    b"22270061",
    b"22270047",
    b"22270049",
    b"22270053",
    b"22270065",
    b"22270063",
    b"22270067",
    b"22270043",
    b"22270041",
    b"AAAAAAA9",
    b"AAAAAAA8",
    b"22040043",
];

/// Whether a 14-char Midea serial's SN8 prefix (the first 8 chars) is on the
/// no-bind whitelist — the gate for attempting the FFA0 control handshake.
pub fn sn8_no_bind(sn: &[u8; 14]) -> bool {
    NO_BIND_SN8.iter().any(|p| sn[..8] == p[..])
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
        if atype == 0xFF
            && data.len() >= 3 + 14
            && data[0] == 0xA8
            && data[1] == 0x06
            && data[2] == 0x01
        {
            let mut sn = [0u8; 14];
            sn.copy_from_slice(&data[3..3 + 14]);
            return Some(sn);
        }
        i += 1 + flen;
    }
    None
}

/// Walk the AD structures and return the device's real MAC embedded in the
/// longer `0x06A8` manufacturer frame, if present.
///
/// The rootKey's ikm is `0xAC + SN8 + MAC6(reversed)` (midea-ble-go's
/// `buildAdvertisData`). The reference reads the MAC from the manufacturer
/// payload at `payload[19:25]` — *not* the on-air address — because the on-air
/// address can be a rotating/resolvable private address that differs from the
/// real MAC. `data` here includes the 2-byte company ID, so the MAC sits at
/// `data[21..27]` (payload offset 19 + 2).
pub fn parse_midea_mac(ad: &[u8]) -> Option<[u8; 6]> {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        let atype = ad[i + 1];
        let data = &ad[i + 2..i + 1 + flen];
        if atype == 0xFF
            && data.len() >= 27
            && data[0] == 0xA8
            && data[1] == 0x06
            && data[2] == 0x01
        {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&data[21..27]);
            return Some(mac);
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

/// The v2 **capability block** — the second `0x06A8` manufacturer block that
/// Midea devices broadcast alongside the serial block. It carries the bind /
/// config posture in a packed byte; the official app's
/// `BleAnalyticalUtil.resolvSecondAgreement` is the reference for the layout:
/// byte 3 = cap bits (devtype / wifi / ble / bind / transport / ota), byte 4 =
/// flags (mesh, region, **isBleController**, bleConfigLight, …), byte 5 = RSSI,
/// bytes 6..12 = WiFi MAC, byte 13 = config error code, byte 14 = extended
/// flags (wired / special / **mesh3** / ai-error / transport-callback).
#[derive(Clone, Copy, Default)]
pub struct Capability {
    /// 0 = single-BLE (direct bind via token write), 1 = combo (WiFi + BLE).
    pub device_ble_type: u8,
    pub wifi_configed: bool,
    pub ble_configed: bool,
    /// The BLE bind is offered — the app's auth gate (`isAuth()`) for single-BLE.
    pub ble_configable: bool,
    pub wifi_configable: bool,
    pub can_bind_by_dev: bool,
    pub can_ble_transport: bool,
    pub can_ble_ota: bool,
    /// Plain BLE-mesh presence (flags byte bit 0).
    pub support_mesh: bool,
    /// "BLE controller" — the device supports the FFA0 direct-control path
    /// (digital remote control, no bind needed; ACs advertise this). Flags
    /// byte bit 4 — a passive predictor that the FFA0 handshake will work.
    pub is_ble_controller: bool,
    pub support_beacon: bool,
    /// Extended MS-BLE 3.0 mesh (ext-flags byte bit 4).
    pub support_mesh3: bool,
}

impl Capability {
    /// Compact log form: `bletype=combo configable ble=[cfg=Y/ok=Y] devbind=Y`.
    pub fn fmt(&self) -> heapless::String<160> {
        let mut s: heapless::String<160> = heapless::String::new();
        use core::fmt::Write;
        let _ = write!(
            s,
            "bletype={} bindable={} ble[cfg={} ok={}] wifi[cfg={} ok={}] devbind={} transport={} ota={} mesh={} controller={} beacon={} mesh3={}",
            if self.device_ble_type != 0 {
                "combo"
            } else {
                "single"
            },
            y(self.ble_configable),
            y(self.ble_configed),
            y(self.ble_configable),
            y(self.wifi_configed),
            y(self.wifi_configable),
            y(self.can_bind_by_dev),
            y(self.can_ble_transport),
            y(self.can_ble_ota),
            y(self.support_mesh),
            y(self.is_ble_controller),
            y(self.support_beacon),
            y(self.support_mesh3),
        );
        s
    }
}

fn y(b: bool) -> &'static str {
    if b { "Y" } else { "N" }
}

/// Parse the capability block from a Midea advertising payload: the `0x06A8`
/// manufacturer block whose `data[2]` is the protocol-version byte `0x02`
/// (distinct from the `0x01` serial block). Bit layout per the app's
/// `resolvSecondAgreement`:
/// `[3]=cap[devtype|wifiCfg|bleCfg|bleCfgable|wifiCfgable|devbind|transport|ota]`,
/// `[13]` more flags (mesh3 bit4), `[14]` bit0 = beacon.
pub fn capability_of_ad(ad: &[u8]) -> Option<Capability> {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        let atype = ad[i + 1];
        let data = &ad[i + 2..i + 1 + flen];
        if atype == 0xFF && data.len() >= 4 && data[0] == 0xA8 && data[1] == 0x06 && data[2] == 0x02
        {
            let cap = data[3];
            let flags = data.get(4).copied().unwrap_or(0);
            return Some(Capability {
                device_ble_type: cap & 0x01,
                wifi_configed: cap & 0x02 != 0,
                ble_configed: cap & 0x04 != 0,
                ble_configable: cap & 0x08 != 0,
                wifi_configable: cap & 0x10 != 0,
                can_bind_by_dev: cap & 0x20 != 0,
                can_ble_transport: cap & 0x40 != 0,
                can_ble_ota: cap & 0x80 != 0,
                // Flags byte (app bArr2[5]): mesh bit0, isBleController bit4.
                support_mesh: flags & 0x01 != 0,
                is_ble_controller: flags & 0x10 != 0,
                support_mesh3: data.len() >= 15 && data[13] & 0x10 != 0,
                support_beacon: data.len() >= 15 && data[14] & 0x01 != 0,
            });
        }
        i += 1 + flen;
    }
    None
}
