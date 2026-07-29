//! Connected Isochronous Streams: setting one up, and tearing it down.
//!
//! A CIS runs on its own access address, on subevents placed relative to this
//! connection's anchor. The offsets and sync delays printed here are what would
//! be needed to follow the stream itself, and the reference event ties them to
//! the ACL connection this PDU arrived on.

use core::fmt::Write;

use super::{error_name, line, send, u16le, u24le, write_interval, write_phys, Decoder};

pub(super) struct Iso;

impl Decoder<u8> for Iso {
    fn keys(&self) -> &'static [u8] {
        &[0x1F, 0x20, 0x21, 0x22]
    }

    fn decode(&self, p: &[u8]) {
        let d = &p[1..];
        match p[0] {
            // LL_CIS_REQ: the central's full stream proposal. The SDU/PDU sizes
            // and intervals, per-direction PHY, and burst/flush numbers are the
            // parameters the RSP/IND then only confirm; the CIS offsets and
            // reference event place the stream against this connection's anchor.
            // Fields are bit-packed little-endian (Core v5.4 Vol 6 Part B
            // §2.4.2.29): a 12-bit Max_SDU with the Framed flag in bit 15, and
            // 20-bit SDU_Intervals in microseconds.
            0x1F if d.len() >= 35 => {
                let mut s = line();
                let _ = write!(s, "cig={} cis={} c->p_phy=", d[0], d[1]);
                write_phys(&mut s, d[2]);
                let _ = s.push_str(" p->c_phy=");
                write_phys(&mut s, d[3]);
                let _ = write!(s, " framed={}", (u16le(d, 4) >> 15) & 1);
                send(s);

                let mut s = line();
                let _ = write!(
                    s,
                    "sdu c->p={}B/{}us p->c={}B/{}us pdu c->p={}B p->c={}B",
                    u16le(d, 4) & 0x0FFF,
                    u24le(d, 8) & 0x0F_FFFF,
                    u16le(d, 6) & 0x0FFF,
                    u24le(d, 11) & 0x0F_FFFF,
                    u16le(d, 14),
                    u16le(d, 16)
                );
                send(s);

                let mut s = line();
                let _ = write!(
                    s,
                    "nse={} sub_int={}us bn={}/{} ft={}/{} iso_int=",
                    d[18], u24le(d, 19), d[22] & 0x0F, d[22] >> 4, d[23], d[24]
                );
                write_interval(&mut s, u16le(d, 25));
                let _ = write!(
                    s,
                    " cis_offset={}..{}us ref_ev={}",
                    u24le(d, 27), u24le(d, 30), u16le(d, 33)
                );
                send(s);
            }
            // LL_CIS_RSP: CIS_Offset_Min(3) CIS_Offset_Max(3) connEventCount(2).
            0x20 if d.len() >= 8 => {
                let mut s = line();
                let _ = write!(
                    s,
                    "cis_offset={}..{}us ref_ev={}",
                    u24le(d, 0), u24le(d, 3), u16le(d, 6)
                );
                send(s);
            }
            // LL_CIS_IND: the stream's own access address and the delays that
            // place its subevents relative to this connection's anchor.
            0x21 if d.len() >= 15 => {
                let mut s = line();
                let _ = write!(
                    s,
                    "aa=0x{:08X} cis_offset={}us cig_sync_delay={}us cis_sync_delay={}us ref_ev={}",
                    u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
                    u24le(d, 4), u24le(d, 7), u24le(d, 10), u16le(d, 13)
                );
                send(s);
            }
            // LL_CIS_TERMINATE_IND: which stream in which group, and why.
            0x22 if d.len() >= 3 => {
                let mut s = line();
                let _ = write!(
                    s,
                    "cig={} cis={} error=0x{:02X} ({})",
                    d[0], d[1], d[2], error_name(d[2])
                );
                send(s);
            }
            _ => {}
        }
    }
}
