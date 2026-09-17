//! Haier U-home appliances (mfg company `0x0929`).
//!
//! Haier devices — e.g. the `U-GWH2111` gas water heater — advertise a 13-byte
//! manufacturer frame (`type 0x10`, embedded address, version, product code;
//! decoded in [`crate::decoder::advert::haier`]) plus a `0xFF01` ServiceData
//! frame (shared with U-tec locks — see `decoder/advert/mod.rs`). The Haier U+
//! app has **no direct-BLE GATT control** (control is its IOTC UDP protocol or
//! the Realtek mesh), so the probe connects and walks the GATT to discover what
//! the device actually serves on a raw connection.

use crate::central::{Conn, Service, walk_services};

/// True if the advertising payload carries a Haier U-home manufacturer frame
/// (company `0x0929`).
pub fn is_haier_advert(ad: &[u8]) -> bool {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        let atype = ad[i + 1];
        let data = &ad[i + 2..i + 1 + flen];
        // 0x0929 is Haier's registered Company ID — the mfg frame's 3rd byte is a
        // model-specific marker (0x10 on some, 0x06 on others), so the CID alone
        // is the reliable discriminator. Requiring a specific marker missed whole
        // model families (e.g. the U-EWHCDD0 water heater, which advertises 0xFF01
        // without the 0x10 marker and was mis-detected as a U-tec lock).
        if atype == 0xFF && data.len() >= 2 && data[0] == 0x29 && data[1] == 0x09 {
            return true;
        }
        i += 1 + flen;
    }
    false
}

/// Probe a Haier appliance: walk the GATT, logging every service / characteristic
/// and reading each readable value — to learn what a raw connection serves
/// (identity? pairing config? a control profile?). Returns the subscription count.
#[allow(dead_code)]
pub(crate) async fn probe(conn: &mut Conn, services: &[Service]) -> u32 {
    walk_services(conn, services, |_vh, _uuid| {}).await
}
