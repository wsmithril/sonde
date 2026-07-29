//! Non-cryptographic hashing.

/// FNV-1a 32-bit hash — the shared fingerprint primitive. Two modes key a
/// logical-device fingerprint off it: BLE-sniff over an advert's AD payload (stable
/// across RPA rotation) and Zigbee over a MAC address.
pub fn fnv1a(data: &[u8]) -> u32 {
    let mut h = 0x811c_9dc5u32;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}
