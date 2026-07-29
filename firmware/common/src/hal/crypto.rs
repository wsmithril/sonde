//! AES-128 ECB via the nRF ECB peripheral, and the BLE `ah` resolvable-address
//! hash built on it.
//!
//! The `ah` hash resolves rotating identities (RPA, CSIP RSI) against
//! compiled-in keys (see [`crate::keys`], gated behind `resolve-identities`);
//! [`aes128_ecb`] also backs the Midea AES-CCM layer
//! ([`crate::device::midea::crypto`]).

use embassy_nrf::pac;

use crate::SyncBuf;

/// ECB scratch block: `KEY[0..16] | CLEARTEXT[16..32] | CIPHERTEXT[32..48]`, all
/// most-significant-octet-first as the ECB peripheral expects. Only the log task
/// calls into here, one block at a time, so a single shared static is safe.
static ECB_DATA: SyncBuf<48> = SyncBuf::new();

/// AES-128 ECB encrypt one block. `key` and `block` are big-endian (octet 0 is
/// most significant), matching the nRF ECB register layout; the result is
/// big-endian too.
fn aes_ecb(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let r = pac::ECB;
    let buf = unsafe { &mut *ECB_DATA.0.get() };
    buf[0..16].copy_from_slice(key);
    buf[16..32].copy_from_slice(block);

    r.ecbdataptr().write_value(ECB_DATA.0.get() as u32);
    r.events_endecb().write_value(0);
    r.events_errorecb().write_value(0);
    r.tasks_startecb().write_value(1);
    while r.events_endecb().read() == 0 && r.events_errorecb().read() == 0 {}

    let mut out = [0u8; 16];
    out.copy_from_slice(&buf[32..48]);
    out
}

/// AES-128 ECB encrypt one block on the nRF ECB peripheral, big-endian in and
/// out. Exposed for building higher-level modes (e.g. AES-CCM) on the hardware
/// block cipher instead of a software AES implementation.
pub fn aes128_ecb(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    aes_ecb(key, block)
}

/// The BLE `ah` random-address hash (Core v5.4 Vol 3 Part H §2.2.2):
/// `ah(k, r) = e(k, r') mod 2^24`, where `r'` is the 24-bit `r` right-justified
/// in a 128-bit zero-padded block. `r` and the returned hash are
/// most-significant-octet first.
pub fn ah(key: &[u8; 16], r: &[u8; 3]) -> [u8; 3] {
    let mut block = [0u8; 16];
    block[13] = r[0];
    block[14] = r[1];
    block[15] = r[2];
    let ct = aes_ecb(key, &block);
    [ct[13], ct[14], ct[15]]
}
