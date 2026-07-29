//! Periodic Advertising Sync Transfer: handing a periodic train to the peer.
//!
//! `LL_PERIODIC_SYNC_IND` carries a whole SyncInfo — the same block a scanner
//! reads from an AUX_ADV_IND — over the connection, so the peer can sync to a
//! periodic advertiser without scanning for it. For a passive observer that is a
//! gift: the access address, CRC init, channel map, interval and offset printed
//! here are exactly what a follower needs to go and receive that periodic train
//! itself. `LL_PERIODIC_SYNC_WR_IND` is the same block with the PAwR response
//! parameters appended.

use core::fmt::Write;

use super::{line, send, u16le, u24le, write_interval, write_phys, Decoder};

pub(super) struct Sync;

impl Decoder<u8> for Sync {
    fn keys(&self) -> &'static [u8] {
        &[0x1C, 0x2A]
    }

    fn decode(&self, p: &[u8]) {
        let d = &p[1..];
        // Both PDUs start with the 20-byte ID + SyncInfo block, then the event
        // counters, sync flags, PHY, AdvA and syncConnEventCount (Core v5.4 Vol 6
        // Part B §2.4.2.24). WR_IND appends the PAwR response parameters.
        if d.len() < 34 {
            return;
        }

        // SyncInfo offset field: a 13-bit offset in units of 30µs or 300µs, with
        // an optional +2.4576s adjustment, giving time to the next periodic event.
        let sf = u16le(d, 2);
        let units = if sf & 0x2000 != 0 { 300u32 } else { 30 };
        let adjust = if sf & 0x4000 != 0 { 2_457_600u32 } else { 0 };
        let offset_us = (sf & 0x1FFF) as u32 * units + adjust;

        let mut s = line();
        let _ = write!(s, "id=0x{:04X} offset={}us interval=", u16le(d, 0), offset_us);
        write_interval(&mut s, u16le(d, 4));
        let _ = s.push_str(" phy=");
        write_phys(&mut s, d[25]);
        send(s);

        // Access address, CRC init and channel map are the periodic train's own
        // link parameters; the SCA rides in the top 3 bits of the last map byte.
        let mut s = line();
        let _ = write!(
            s,
            "aa=0x{:08X} crc_init=0x{:06X} sca={} chan_map=",
            u32::from_le_bytes([d[11], d[12], d[13], d[14]]),
            u24le(d, 15),
            d[10] >> 5
        );
        for (i, b) in d[6..11].iter().enumerate() {
            let _ = write!(s, "{:02X}", if i == 4 { b & 0x1F } else { *b });
        }
        send(s);

        let mut s = line();
        let _ = write!(
            s,
            "pa_evt={} conn_ev={} last_pa_ev={} sync_conn_ev={} adva=",
            u16le(d, 18), u16le(d, 20), u16le(d, 22), u16le(d, 32)
        );
        for (i, b) in d[26..32].iter().rev().enumerate() {
            if i > 0 {
                let _ = s.push(':');
            }
            let _ = write!(s, "{:02X}", b);
        }
        send(s);

        // LL_PERIODIC_SYNC_WR_IND: response access address and the PAwR subevent
        // layout the peer will use to answer.
        if p[0] == 0x2A && d.len() >= 42 {
            let mut s = line();
            let _ = write!(
                s,
                "rsp_aa=0x{:08X} nse={} subevt_int={} rsp_slot_delay={} rsp_slot_spacing={}",
                u32::from_le_bytes([d[34], d[35], d[36], d[37]]),
                d[38], d[39], d[40], d[41]
            );
            send(s);
        }
    }
}
