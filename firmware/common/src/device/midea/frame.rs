//! Midea three-layer transport frame builders/parsers — the encode side of the
//! control channel (write to GATT `0xFFA1`), ported from the midea-ble-go
//! reference (`internal/proto/frame.go`).
//!
//! ```text
//! conn:  AA 55 [len][seq][type]  body  [chk]     len = body+4, chk = -Σ(bytes[2..end-1])
//! sec:   [cmd][seq][len] body                    no checksum (AES-CCM tag covers it)
//! biz:   [type][len] 00 body [chk]               len = body+4, chk = -Σ(bytes[0..end-1])
//! ```
//!
//! These are pure and device-agnostic; encrypting the security body (rootKey for
//! t2, sessionKey for t3) is a separate step the crypto layer will own. Not wired
//! to any mode yet.
#![allow(dead_code)]

/// Output buffer for a built frame. Sized for the largest one — the c3
/// handshake frame (64-byte public key + inner AES-CCM blob, wrapped in
/// security + conn ≈ 120 bytes).
pub type Frame = heapless::Vec<u8, 160>;

/// conn-layer frame type.
pub const T1: u8 = 0x01; // connection handshake (get-version)
pub const T2: u8 = 0x02; // rootKey-encrypted security frame (c1..c3)
pub const T3: u8 = 0x03; // sessionKey-encrypted security frame (c4 business)

/// security-layer command.
pub const C1: u8 = 0x01;
pub const C2: u8 = 0x02;
pub const C3: u8 = 0x03;
pub const C4: u8 = 0x04;

/// Two's-complement of the byte sum: `(-Σb) & 0xFF`.
fn checksum_neg(b: &[u8]) -> u8 {
    b.iter().fold(0u8, |a, &x| a.wrapping_sub(x))
}

/// Encode a connection-layer frame `AA 55 [len][seq][type] body [chk]`.
/// Returns `None` if the body is too long for the 8-bit length field.
pub fn encode_conn(typ: u8, body: &[u8], seq: u8) -> Option<Frame> {
    let length = body.len() + 4;
    if length > 255 {
        return None;
    }
    let mut out = Frame::new();
    out.extend_from_slice(&[0xAA, 0x55, length as u8, seq, typ]).ok()?;
    out.extend_from_slice(body).ok()?;
    let chk = checksum_neg(&out[2..]);
    out.push(chk).ok()?;
    Some(out)
}

/// Parse a connection-layer frame, returning `(type, seq, body)`.
pub fn decode_conn(buf: &[u8]) -> Option<(u8, u8, &[u8])> {
    if buf.len() < 6 || buf[0] != 0xAA || buf[1] != 0x55 {
        return None;
    }
    let length = buf[2] as usize;
    let body_len = length.checked_sub(4)?;
    if 5 + body_len > buf.len() {
        return None;
    }
    Some((buf[4], buf[3], &buf[5..5 + body_len]))
}

/// Encode a security-layer frame `[cmd][seq][len] body` (no checksum).
pub fn encode_security(cmd: u8, body: &[u8], seq: u8) -> Option<Frame> {
    let mut out = Frame::new();
    out.extend_from_slice(&[cmd, seq, body.len() as u8]).ok()?;
    out.extend_from_slice(body).ok()?;
    Some(out)
}

/// Parse a security-layer frame, returning `(cmd, seq, body)`.
pub fn decode_security(buf: &[u8]) -> Option<(u8, u8, &[u8])> {
    if buf.len() < 3 {
        return None;
    }
    let end = (3 + buf[2] as usize).min(buf.len());
    Some((buf[0], buf[1], &buf[3..end]))
}

/// Encode a business-layer frame `[type][len] 00 body [chk]`.
pub fn encode_biz(typ: u8, body: &[u8]) -> Option<Frame> {
    let length = body.len() + 4;
    if length > 255 {
        return None;
    }
    let mut out = Frame::new();
    out.resize(length, 0).ok()?;
    out[0] = typ;
    out[1] = length as u8;
    // out[2] reserved 0
    out[3..3 + body.len()].copy_from_slice(body);
    out[length - 1] = checksum_neg(&out[..length - 1]);
    Some(out)
}

/// Extract the business-layer body (`buf[3..len-1]`).
pub fn decode_biz(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 4 {
        return None;
    }
    Some(&buf[3..buf.len() - 1])
}
