//! LE Power Control: what each peer is transmitting at, and what it is asked to
//! change to.
//!
//! Delta and TxPower are signed dBm and are per-PHY, so a link that has just
//! switched PHY renegotiates power as well. The values are the sender's own
//! report of its transmit power, which is what makes a captured RSSI
//! interpretable as path loss rather than as an unknown.

use core::fmt::Write;

use super::{line, send, write_phys, Decoder};

pub(super) struct Power;

impl Decoder<u8> for Power {
    fn keys(&self) -> &'static [u8] {
        &[0x23, 0x24, 0x25]
    }

    fn decode(&self, p: &[u8]) {
        let d = &p[1..];
        match p[0] {
            // LL_POWER_CONTROL_REQ: PHY(1) Delta(1) TxPower(1).
            0x23 if d.len() >= 3 => {
                let mut s = line();
                let _ = s.push_str("phy=");
                write_phys(&mut s, d[0]);
                let _ = write!(s, " delta={}dB tx_power={}dBm", d[1] as i8, d[2] as i8);
                send(s);
            }
            // LL_POWER_CONTROL_RSP: MinMaxReached(1) Delta(1) TxPower(1) APR(1).
            // APR is the acceptable power reduction the sender still has margin
            // for.
            0x24 if d.len() >= 4 => {
                let mut s = line();
                let _ = write!(
                    s,
                    "limits=0x{:02X} delta={}dB tx_power={}dBm apr={}dB",
                    d[0], d[1] as i8, d[2] as i8, d[3]
                );
                send(s);
            }
            // LL_POWER_CHANGE_IND: PHY(1) Delta(1) TxPower(1) MinMaxReached(1).
            0x25 if d.len() >= 4 => {
                let mut s = line();
                let _ = s.push_str("phy=");
                write_phys(&mut s, d[0]);
                let _ = write!(
                    s,
                    " delta={}dB tx_power={}dBm limits=0x{:02X}",
                    d[1] as i8, d[2] as i8, d[3]
                );
                send(s);
            }
            _ => {}
        }
    }
}
