//! Encryption start-up, and the last plaintext a passive follower gets.
//!
//! `LL_ENC_REQ` / `LL_ENC_RSP` exchange the two halves of the session key
//! diversifier and initialisation vector; `LL_START_ENC_REQ` and
//! `LL_START_ENC_RSP` are empty and everything after them is ciphertext. Rand
//! and EDIV name the long-term key the pair is about to use and are the only
//! fields here that are not fresh session randomness, so they are what ties a
//! capture to an earlier pairing.

use core::fmt::Write;

use super::{line, send, u16le, write_hex_be, Decoder};

pub(super) struct Encryption;

impl Decoder<u8> for Encryption {
    fn keys(&self) -> &'static [u8] {
        &[0x03, 0x04]
    }

    fn decode(&self, p: &[u8]) {
        let d = &p[1..];
        match p[0] {
            // LL_ENC_REQ: Rand(8) EDIV(2) SKDm(8) IVm(4).
            0x03 if d.len() >= 22 => {
                let mut s = line();
                let _ = s.push_str("rand=");
                write_hex_be(&mut s, &d[..8]);
                let _ = write!(s, " ediv=0x{:04X}", u16le(d, 8));
                send(s);
                let mut s = line();
                let _ = s.push_str("skd_c=");
                write_hex_be(&mut s, &d[10..18]);
                let _ = s.push_str(" iv_c=");
                write_hex_be(&mut s, &d[18..22]);
                send(s);
            }
            // LL_ENC_RSP: SKDs(8) IVs(4) — the peripheral's half of the session
            // nonce.
            0x04 if d.len() >= 12 => {
                let mut s = line();
                let _ = s.push_str("skd_p=");
                write_hex_be(&mut s, &d[..8]);
                let _ = s.push_str(" iv_p=");
                write_hex_be(&mut s, &d[8..12]);
                send(s);
            }
            _ => {}
        }
    }
}
