//! JOMOO smart bathroom devices (smart toilets / showers).
//!
//! The advert (Telink SoC, UUID16 `FFE0`/`00F0`, name `JOMOO_SMART_…`) has no
//! distinctive company, so detection is by the name. On connect the device serves
//! a Telink `0xFFF0` control profile (write `0xFFF2`, notify `0xFFF1`) — the
//! smart-toilet protocol documented by the AXENT (JOMOO family) Home Assistant
//! integration: 32-byte `02 0A … 0B 04` command frames, `02 0E 30 …` status
//! frames carrying seat / water-temp / nozzle / flush state. The probe walks the
//! GATT to map that profile.

use crate::central::{Conn, Service, walk_services};

/// True if the advertising payload names a JOMOO smart device (`JOMOO…`).
pub fn is_jomoo_advert(ad: &[u8]) -> bool {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        let atype = ad[i + 1];
        let data = &ad[i + 2..i + 1 + flen];
        if atype == 0x09 && data.len() >= 5 && data[..5].eq_ignore_ascii_case(b"JOMOO") {
            return true;
        }
        i += 1 + flen;
    }
    false
}

/// Probe a JOMOO device: walk the GATT to map the `0xFFF0` control profile
/// (write `0xFFF2` + notify `0xFFF1`). Returns the subscription count.
#[allow(dead_code)]
pub(crate) async fn probe(conn: &mut Conn, services: &[Service]) -> u32 {
    walk_services(conn, services, |_vh, _uuid| {}).await
}
