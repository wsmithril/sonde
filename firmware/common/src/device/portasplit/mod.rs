//! Midea "PortaSplit" portable air conditioner — the OEM BLE scheme.
//!
//! Unlike the rest of the Midea family (0xFFA0 + ECDH handshake), the
//! PortaSplit product line exposes a **write-only** service `0xFF02` /
//! characteristic `0xFF01` and derives its control AES key **entirely from the
//! advertisement** — no handshake, no binding. The manufacturer payload carries
//! `MAC(6) ‖ SN8(8) ‖ token(4)` in plaintext; the session key is
//! `AES-128-ECB(mac ‖ sn[..6] ‖ token, "MideaOemBleKey20")`. Each control frame
//! is `AA 55 ‖ AES-128-ECB(block) ‖ 55 AA` where the block is
//! `A5 5A 0C 01 seq power mode fan temp xor-checksum 5A A5` + PKCS#7 padding.
//!
//! Layout and frame format follow the public flipper-midea-ble project.
//! HARDWARE-UNVERIFIED against a live PortaSplit unit: the advertised company ID
//! is `0x0002` (not the `0x06A8` of the rest of the family), taken from that
//! project's captured layout.

use crate::hal::crypto::aes128_ecb;

/// Service UUID of the PortaSplit OEM control channel.
pub const SERVICE_UUID: u16 = 0xFF02;
/// The write-only control characteristic.
pub const WRITE_UUID: u16 = 0xFF01;

/// The static OEM magic key the firmware derives the control key under.
const OEM_MAGIC_KEY: [u8; 16] = *b"MideaOemBleKey20";

/// True if the advertising payload carries a PortaSplit OEM manufacturer frame
/// (company `0x0002`, product type `0xAC`, 21+ bytes).
pub fn is_portasplit_advert(ad: &[u8]) -> bool {
    material_of_ad(ad).is_some()
}

/// Extract the flat key material (`mac ‖ sn ‖ token`, 18 bytes) from a
/// PortaSplit advert, if present. Also the advert-classification entry point.
pub fn material_of_ad(ad: &[u8]) -> Option<[u8; 18]> {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        let atype = ad[i + 1];
        let data = &ad[i + 2..i + 1 + flen];
        // Manufacturer data: [company 0x0002 LE][product 0xAC][mac 6][sn 8][token 4].
        if atype == 0xFF
            && data.len() >= 21
            && data[0] == 0x02
            && data[1] == 0x00
            && data[2] == 0xAC
        {
            let mut m = [0u8; 18];
            m[..6].copy_from_slice(&data[3..9]); // mac
            m[6..14].copy_from_slice(&data[9..17]); // sn8
            m[14..18].copy_from_slice(&data[17..21]); // token
            return Some(m);
        }
        i += 1 + flen;
    }
    None
}

/// Derive the control AES key from the advert material:
/// `AES-128-ECB(mac ‖ sn[..6] ‖ token, "MideaOemBleKey20")`.
pub fn derive_key(mat: &[u8; 18]) -> [u8; 16] {
    let mut material = [0u8; 16];
    material[..6].copy_from_slice(&mat[..6]); // mac
    material[6..12].copy_from_slice(&mat[6..12]); // sn[..6]
    material[12..16].copy_from_slice(&mat[14..18]); // token
    aes128_ecb(&OEM_MAGIC_KEY, &material)
}

/// Build a 20-byte control write for the PortaSplit channel: the `A5 5A` command
/// block (power/mode/fan/temp + XOR checksum), AES-ECB under the derived key,
/// wrapped in `AA 55 … 55 AA`. Kept for a future control feature — the recon
/// probe never sends state-changing writes.
#[allow(dead_code)]
pub fn build_command(
    key: &[u8; 16],
    seq: u8,
    power: bool,
    mode: u8,
    fan: u8,
    temp: u8,
) -> [u8; 20] {
    let mut plain = [0u8; 16];
    plain[0] = 0xA5;
    plain[1] = 0x5A;
    plain[2] = 0x0C; // plain payload length
    plain[3] = 0x01; // command type = set state
    plain[4] = seq;
    plain[5] = u8::from(power);
    plain[6] = mode;
    plain[7] = fan;
    plain[8] = temp;
    plain[9] = plain[5] ^ plain[6] ^ plain[7] ^ plain[8]; // checksum
    plain[10] = 0x5A;
    plain[11] = 0xA5;
    plain[12..16].fill(0x04); // PKCS#7
    let enc = aes128_ecb(key, &plain);
    let mut out = [0u8; 20];
    out[0] = 0xAA;
    out[1] = 0x55;
    out[2..18].copy_from_slice(&enc);
    out[18] = 0x55;
    out[19] = 0xAA;
    out
}
