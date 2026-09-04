//! U-tec / ULTRALOQ smart locks.
//!
//! U-tec locks (branded ULTRALOQ, names like `U-AC…`) advertise a proprietary
//! service-data frame under 16-bit UUID `0xFF01` — a leading type byte followed
//! by lock-state / rolling-identifier bytes (decoded in
//! [`crate::decoder::advert::utec`]). The GATT side exposes a token
//! characteristic (0x7220) whose value, combined with a static salt, forms the
//! unlock AES key (per public CVE research on the UL3 BT). Recon detects the
//! advert and, on connect, walks the GATT — the central's `read_value` reads
//! and logs every readable value, including the 0x7220 token.

use crate::central::{Conn, Service, walk_services};

/// True if the advertising payload carries a U-tec lock's ServiceData16 frame
/// (UUID 0xFF01).
pub fn is_utech_advert(ad: &[u8]) -> bool {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        if ad[i + 1] == 0x16 && flen >= 4 && ad[i + 2] == 0x01 && ad[i + 3] == 0xFF {
            return true;
        }
        i += 1 + flen;
    }
    false
}

/// Probe a U-tec lock: walk the GATT, which reads and logs every readable
/// characteristic (including the 0x7220 token). Returns the subscription count.
pub(crate) async fn probe(conn: &mut Conn, services: &[Service]) -> u32 {
    walk_services(conn, services, |_vh, _uuid| {}).await
}
