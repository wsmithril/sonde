//! Hisense smart-life appliances (e.g. the `HIS-242a` AC).
//!
//! Hisense devices advertise ServiceData16 `0xF005`. From the app's Dart
//! decompile (`com.hisense.ms.fly2tv`, Flutter/DexVMP): appliance control (wine
//! cabinet, fridge, water heater, AC) runs over the Hi-Smart cloud-HTTP + MQTT
//! plane (`iot-aihome.hismarttv.com/4.0/iot/devices/…`, `_ignoreMqttTimer`), not
//! a direct BLE channel. The one BLE-GATT controller in the app is the pan-tilt
//! camera (`PanTiltCommandHelper`, custom base `3a69…587e61`, SIG codes
//! `0x180B`/`0x2A12`/`0x2A13`, `writeData cmd` + notify). So a Hisense
//! appliance's BLE is identity/onboarding; the probe connects and GATT-walks to
//! discover empirically what a raw connection actually serves.

use crate::central::{Conn, Service, walk_services};

/// True if the advertising payload carries a Hisense ServiceData16 frame
/// (UUID `0xF005`).
pub fn is_hisense_advert(ad: &[u8]) -> bool {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        let atype = ad[i + 1];
        let data = &ad[i + 2..i + 1 + flen];
        if atype == 0x16 && flen >= 2 && data[0] == 0x05 && data[1] == 0xF0 {
            return true;
        }
        i += 1 + flen;
    }
    false
}

/// Probe a Hisense appliance: connect and GATT-walk to discover what a raw
/// connection serves (identity? onboarding config? the pan-tilt camera's
/// `3a69…` profile?). Returns the subscription count.
#[allow(dead_code)]
pub(crate) async fn probe(conn: &mut Conn, services: &[Service]) -> u32 {
    walk_services(conn, services, |_vh, _uuid| {}).await
}
