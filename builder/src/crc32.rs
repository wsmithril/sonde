//! CRC-32/ISO-HDLC (reflected, poly 0xEDB88320) — the same algorithm used by
//! `firmware/build.rs` and the firmware's provisioning verify, so the checksum
//! the host sends matches what the device computes over the written bytes.

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
