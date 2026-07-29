//! Sony manufacturer data (Company ID 0x012D).
//!
//! There is no official public spec for Sony's advertising format. The only
//! documented layout is for Sony *cameras* (reverse-engineered): a 2-byte device
//! category + 1-byte protocol version + model/status bytes. Headphones/audio
//! reuse the same skeleton with different, undocumented category codes, so we
//! decode the category + version and leave the model/status as a hexdump.
//!
//! For cameras (category 0x0003) the status region carries a capability/pairing
//! flags byte tagged `0x22`; the tag and the flag bits below were reverse-
//! engineered by the freemote project (https://github.com/coral/freemote,
//! `src/BLECamera.cpp`). Decoding it turns a passive sniff into "this camera is
//! advertising that it is open to pair with a BLE remote".

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Sony Corporation — manufacturer data (Company ID 0x012D).
pub(super) struct Sony;
impl super::VendorDecoder for Sony {
    fn company_ids(&self) -> &'static [u16] { &[0x012D] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 3 {
            // Too short for the category+version header — dump what we have.
            hexdump(body, ctx.base, 6);
            return;
        }
        let cat = u16::from_le_bytes([body[0], body[1]]);
        let ver = body[2];
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Sony: category=0x{:04X} ({}) ver=0x{:02X} (unofficial) len={}",
            cat, Self::category(cat), ver, body.len() - 3);
        emit(s);

        // Camera capability/pairing flags: a 0x22 tag in the status region is
        // followed by one flags byte (freemote, src/BLECamera.cpp). Scan past the
        // 3-byte header so a header byte can't false-match the tag.
        if cat == 0x0003
            && let Some(rel) = body[3..].iter().position(|&b| b == 0x22)
            && let Some(&flags) = body.get(3 + rel + 1)
        {
            let mut f: LogStr = LogStr::new();
            let _ = write!(f, "      camera flags=0x{:02X}", flags);
            if flags & 0x80 != 0 { let _ = write!(f, " pairing-supported"); }
            if flags & 0x40 != 0 { let _ = write!(f, " pairing-enabled"); }
            if flags & 0x20 != 0 { let _ = write!(f, " location-supported"); }
            if flags & 0x10 != 0 { let _ = write!(f, " location-enabled"); }
            if flags & 0x02 != 0 { let _ = write!(f, " remote-enabled"); }
            // Open to bond with a BLE remote when both are advertised.
            if flags & 0x42 == 0x42 { let _ = write!(f, " [ready-to-pair]"); }
            emit(f);
        }
        hexdump(&body[3..], ctx.base + 3, 6);
    }
}

impl Sony {
    fn category(c: u16) -> &'static str {
        match c {
            0x0003 => "camera",       // documented
            0x0004 | 0x0013 => "audio?", // observed on headphones/earbuds, unverified
            _ => "?",
        }
    }
}
