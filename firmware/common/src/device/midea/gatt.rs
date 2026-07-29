//! Midea control channel over GATT (service `0xFFA0`, write `0xFFA1`, notify
//! `0xFFA2`) — passive decode of the frame structure seen in a capture.
//!
//! Every message on the channel is wrapped in a three-layer frame; only the two
//! outer headers are plaintext:
//!
//! ```text
//! conn:  AA 55 [len][seq][type]  body  [checksum]   len = body+4, type t1/t2/t3
//! sec:   [cmd][seq][len] body                       cmd c1..c4, body ciphertext
//! biz:   (inside the decrypted security body)        set/query/status commands
//! ```
//!
//! From a passive capture the conn + security headers give the sequence numbers,
//! frame type and handshake phase. The security body is AES-CCM ciphertext:
//!
//! * `t2` frames (handshake c1..c3) use the **rootKey**, and
//!   `rootKey = HKDF-SHA256(0xAC || SN8 || MAC_reversed, info="midea_bleapp")`.
//!   The SN and MAC are both broadcast in the 0x06A8 advertisement, so this key
//!   — and therefore the handshake body — is recoverable by a passive listener.
//! * `t3` frames (business c4) use the ECDH-P256 **sessionKey**; a passive
//!   observer never sees either private key, so these stay opaque.
//!
//! Layout per the midea-ble-go reference (`docs/protocol.md`).

use core::fmt::Write;

use crate::decoder::protocol::{line, send};

/// Midea control-channel GATT UUIDs (16-bit, in the Bluetooth base range).
pub const SERVICE_UUID: u16 = 0xFFA0;
pub const WRITE_UUID: u16 = 0xFFA1; // client → device (write-with-response)
pub const NOTIFY_UUID: u16 = 0xFFA2; // device → client (notify/indicate)

/// Role of a Midea characteristic within the control profile.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Service,
    Write,
    Notify,
}

/// A discovered, controllable Midea control profile: the value handles to write
/// commands to (FFA1) and receive replies from (FFA2).
#[derive(Clone, Copy)]
pub struct Profile {
    pub write_h: u16,
    pub notify_h: u16,
}

/// The little-endian on-air form of the Bluetooth Base UUID, first 12 bytes; a
/// 16-bit UUID sits at bytes 12..14 with 14..16 zero.
const BASE_LE: [u8; 12] = [
    0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00,
];

/// Extract a 16-bit UUID from an on-air ATT UUID (2-byte, or 16-byte in the
/// Bluetooth base range). `None` for a non-base 128-bit UUID.
pub fn uuid16(uuid: &[u8]) -> Option<u16> {
    match uuid.len() {
        2 => Some(u16::from_le_bytes([uuid[0], uuid[1]])),
        16 if uuid[..12] == BASE_LE && uuid[14] == 0 && uuid[15] == 0 => {
            Some(u16::from_le_bytes([uuid[12], uuid[13]]))
        }
        _ => None,
    }
}

/// Classify a characteristic/service UUID as a Midea control-profile role.
pub fn role(uuid: &[u8]) -> Option<Role> {
    match uuid16(uuid)? {
        SERVICE_UUID => Some(Role::Service),
        WRITE_UUID => Some(Role::Write),
        NOTIFY_UUID => Some(Role::Notify),
        _ => None,
    }
}

/// Frame type (conn layer byte 4) → (label, which key encrypts the body).
fn conn_type(t: u8) -> (&'static str, &'static str) {
    match t {
        0x01 => ("t1", "plaintext"),
        0x02 => ("t2", "rootKey-enc"),
        0x03 => ("t3", "sessionKey-enc"),
        _ => ("t?", "?"),
    }
}

/// Security-layer command (byte 0) → handshake/business phase name.
fn sec_cmd(c: u8) -> &'static str {
    match c {
        0x01 => "c1",
        0x02 => "c2",
        0x03 => "c3",
        0x04 => "c4",
        _ => "c?",
    }
}

/// Decode the plaintext headers of a Midea control frame carried in an ATT
/// value. Does nothing when the value is not a Midea frame (`AA 55` sync).
pub fn frame(v: &[u8]) {
    if v.len() < 6 || v[0] != 0xAA || v[1] != 0x55 {
        return;
    }
    let length = v[2] as usize; // bytes after the AA 55 sync = body + 4
    let total = 2 + length;
    if length < 4 || total > v.len() {
        return;
    }
    let seq = v[3];
    let (tn, key) = conn_type(v[4]);

    // Checksum covers the length byte through the byte before the checksum.
    let sum = v[2..total - 1].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    let chk_ok = v[total - 1] == 0u8.wrapping_sub(sum);

    let mut s = line();
    let _ = write!(s, "  Midea conn: seq={} type={} ({}) len={} chk={}",
        seq, tn, key, length, if chk_ok { "ok" } else { "BAD" });
    let body = &v[5..total - 1];
    if matches!(v[4], 0x02 | 0x03) && body.len() >= 3 {
        let _ = write!(s, " -> sec {} seq={} enc-body={}B",
            sec_cmd(body[0]), body[1], body.len().saturating_sub(3));
    }
    send(s);
}
