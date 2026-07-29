//! Midea control-channel crypto, ported from midea-ble-go
//! (`internal/proto/crypto.go`).
//!
//! * **rootKey** = `HKDF-SHA256(ikm = 0xAC‖SN8‖MAC_reversed, salt = ∅,
//!   info = "midea_bleapp")[..16]` — the SN and MAC are broadcast in the 0x06A8
//!   advertisement, so a passive listener can derive this and decrypt the `t2`
//!   handshake frames.
//! * **sessionKey** = `SHA-256( P-256_ECDH_x(myPriv, peerPub) )[..16]` — used for
//!   `t3` business frames; needs a private key, so it is only reachable when this
//!   node performs the handshake itself (active control), not passively.
//! * Message crypto is **AES-128-CCM** (nonce 8, tag 8): `nonce ‖ ct ‖ tag`. The
//!   AES block is run on the nRF **ECB peripheral** ([`crate::hal::crypto::aes128_ecb`]),
//!   so only the CCM construction (CTR + CBC-MAC) is software.

#![allow(dead_code)]

use sha2::{Digest, Sha256};

use crate::hal::crypto::aes128_ecb;
use super::frame::Frame;

// AES-CCM parameters used by Midea: 8-byte tag (M) and a 7-byte length field (L),
// which fixes the nonce at 15 - L = 8 bytes.
const M: usize = 8;
const L: usize = 7;

// ── key derivation ──────────────────────────────────────────────────────────

/// Reconstruct the HKDF input the appliance uses: `0xAC ‖ SN[..8] ‖ MAC_reversed`
/// (`internal/ble/scanner.go`). `sn` is the ASCII short serial; only its first 8
/// bytes are used. `mac` is the appliance's real address, most-significant first.
pub fn advertis_data(sn: &[u8], mac: &[u8; 6]) -> [u8; 15] {
    let mut out = [0u8; 15];
    out[0] = 0xAC;
    let n = sn.len().min(8);
    out[1..1 + n].copy_from_slice(&sn[..n]); // shorter SN leaves trailing zeros
    for i in 0..6 {
        out[9 + i] = mac[5 - i]; // reversed
    }
    out
}

/// HMAC-SHA256 over the concatenation of `chunks`.
fn hmac_sha256(key: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    for c in chunks {
        inner.update(c);
    }
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(ih);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// `rootKey = HKDF-SHA256(ikm, salt = ∅, info = "midea_bleapp")[..16]`. An empty
/// salt is HashLen zero bytes (RFC 5869), matching the Go reference.
pub fn derive_root_key(advertis_data: &[u8]) -> [u8; 16] {
    let prk = hmac_sha256(&[0u8; 32], &[advertis_data]); // extract
    let t1 = hmac_sha256(&prk, &[b"midea_bleapp", &[0x01]]); // expand, one block
    let mut out = [0u8; 16];
    out.copy_from_slice(&t1[..16]);
    out
}

// ── AES-128-CCM on the hardware ECB block ───────────────────────────────────

/// CCM counter block `A_i = [L-1] ‖ nonce(8) ‖ counter(7, big-endian)`.
fn ctr_block(nonce: &[u8; 8], counter: u64) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = (L - 1) as u8;
    a[1..9].copy_from_slice(nonce);
    a[9..16].copy_from_slice(&counter.to_be_bytes()[1..8]);
    a
}

/// CBC-MAC over `pt` (no associated data), returning the 8-byte tag `T`.
fn cbc_mac(key: &[u8; 16], nonce: &[u8; 8], pt: &[u8]) -> [u8; M] {
    // B0 = flags ‖ nonce ‖ len. flags = 8*((M-2)/2) + (L-1), Adata bit clear.
    let mut b0 = [0u8; 16];
    b0[0] = (8 * ((M as u8 - 2) / 2)) | (L as u8 - 1);
    b0[1..9].copy_from_slice(nonce);
    b0[9..16].copy_from_slice(&(pt.len() as u64).to_be_bytes()[1..8]);
    let mut x = aes128_ecb(key, &b0);
    let mut i = 0;
    while i < pt.len() {
        let mut blk = [0u8; 16];
        let n = core::cmp::min(16, pt.len() - i);
        blk[..n].copy_from_slice(&pt[i..i + n]);
        for j in 0..16 {
            blk[j] ^= x[j];
        }
        x = aes128_ecb(key, &blk);
        i += 16;
    }
    let mut t = [0u8; M];
    t.copy_from_slice(&x[..M]);
    t
}

/// CTR-mode keystream XOR of `data` (starting at counter 1), appended to `out`.
fn ctr_crypt(key: &[u8; 16], nonce: &[u8; 8], data: &[u8], out: &mut Frame) -> Option<()> {
    let mut i = 0;
    let mut counter = 1u64;
    while i < data.len() {
        let s = aes128_ecb(key, &ctr_block(nonce, counter));
        let n = core::cmp::min(16, data.len() - i);
        for j in 0..n {
            out.push(data[i + j] ^ s[j]).ok()?;
        }
        i += 16;
        counter += 1;
    }
    Some(())
}

/// AES-128-CCM encrypt: returns `nonce ‖ ciphertext ‖ tag`. The caller supplies
/// the nonce (the reference draws it from a CSPRNG per message).
pub fn cipher_msg(key: &[u8; 16], pt: &[u8], nonce: &[u8; 8]) -> Option<Frame> {
    let t = cbc_mac(key, nonce, pt);
    let s0 = aes128_ecb(key, &ctr_block(nonce, 0));
    let mut out = Frame::new();
    out.extend_from_slice(nonce).ok()?;
    ctr_crypt(key, nonce, pt, &mut out)?;
    for j in 0..M {
        out.push(t[j] ^ s0[j]).ok()?; // encrypted MIC
    }
    Some(out)
}

/// AES-128-CCM decrypt `nonce ‖ ciphertext ‖ tag`. Returns the plaintext only
/// when the tag verifies. This is the passive path for `t2` handshake frames.
pub fn decipher_msg(key: &[u8; 16], blob: &[u8]) -> Option<Frame> {
    if blob.len() < 8 + M {
        return None;
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&blob[..8]);
    let ct = &blob[8..blob.len() - M];
    let recv_tag = &blob[blob.len() - M..];

    let mut pt = Frame::new();
    ctr_crypt(key, &nonce, ct, &mut pt)?;
    let t = cbc_mac(key, &nonce, &pt);
    let s0 = aes128_ecb(key, &ctr_block(&nonce, 0));
    let mut diff = 0u8;
    for j in 0..M {
        diff |= (t[j] ^ s0[j]) ^ recv_tag[j];
    }
    if diff != 0 {
        return None;
    }
    Some(pt)
}

// ── P-256 ECDH session key (active control only) ────────────────────────────

/// `sessionKey = SHA-256( ECDH_x(myPriv, peerPub) )[..16]`. `peer_pub64` is the
/// raw `X‖Y` point (no 0x04 prefix). `None` if either key is invalid.
pub fn derive_session_key(my_priv: &[u8; 32], peer_pub64: &[u8; 64]) -> Option<[u8; 16]> {
    use p256::ecdh::diffie_hellman;
    use p256::{PublicKey, SecretKey};

    let sk = SecretKey::from_bytes(my_priv.into()).ok()?;
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(peer_pub64);
    let pk = PublicKey::from_sec1_bytes(&sec1).ok()?;

    let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let mut out = [0u8; 16];
    out.copy_from_slice(&Sha256::digest(shared.raw_secret_bytes())[..16]);
    Some(out)
}

/// Generate a P-256 keypair, returning `(priv[32], pub64 = X‖Y)`. Needs a CSPRNG
/// (seed from the nRF TRNG). Used only when this node runs the handshake.
pub fn create_keypair<R>(rng: &mut R) -> ([u8; 32], [u8; 64])
where
    R: p256::elliptic_curve::rand_core::RngCore + p256::elliptic_curve::rand_core::CryptoRng,
{
    use p256::EncodedPoint;
    use p256::SecretKey;

    let sk = SecretKey::random(rng);
    let priv_b: [u8; 32] = sk.to_bytes().into();
    let point = EncodedPoint::from(sk.public_key());
    let full = point.as_bytes(); // 0x04 ‖ X ‖ Y
    let mut pub64 = [0u8; 64];
    pub64.copy_from_slice(&full[1..65]);
    (priv_b, pub64)
}
