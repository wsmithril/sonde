//! PHY negotiation and the Constant Tone Extension request.
//!
//! `LL_PHY_UPDATE_IND` is the one PDU here that changes what a follower must do:
//! at its instant the link moves to 2M or Coded, and a receiver configured for
//! 1M stops hearing it. The preceding REQ/RSP pair only states what each side is
//! willing to use.

use core::fmt::Write;

use super::{line, send, u16le, write_phys, Decoder};

pub(super) struct Phy;

impl Decoder<u8> for Phy {
    fn keys(&self) -> &'static [u8] {
        &[0x16, 0x17, 0x18, 0x1A]
    }

    fn decode(&self, p: &[u8]) {
        let d = &p[1..];
        match p[0] {
            // LL_PHY_REQ / _RSP: the PHYs the sender is willing to use each way.
            0x16 | 0x17 if d.len() >= 2 => {
                let mut s = line();
                let _ = s.push_str("tx_phys=");
                write_phys(&mut s, d[0]);
                let _ = s.push_str(" rx_phys=");
                write_phys(&mut s, d[1]);
                send(s);
            }
            // LL_PHY_UPDATE_IND: the PHY each direction switches to at the
            // instant. A zero field means that direction is unchanged.
            0x18 if d.len() >= 4 => {
                let mut s = line();
                let _ = s.push_str("c_to_p=");
                write_phys(&mut s, d[0]);
                let _ = s.push_str(" p_to_c=");
                write_phys(&mut s, d[1]);
                let _ = write!(s, " instant={}", u16le(d, 2));
                send(s);
            }
            // LL_CTE_REQ: MinCTELenReq in the low five bits, CTETypeReq in the
            // top two. Length is in 8 µs units.
            0x1A if !d.is_empty() => {
                let mut s = line();
                let ty = match d[0] >> 6 {
                    0 => "AoA",
                    1 => "AoD-1us",
                    _ => "AoD-2us",
                };
                let _ = write!(s, "min_cte_len={}us type={}", (d[0] & 0x1F) as u16 * 8, ty);
                send(s);
            }
            _ => {}
        }
    }
}
