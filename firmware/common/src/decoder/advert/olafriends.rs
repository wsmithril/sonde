//! "Ola Friends" TWS earbud manufacturer data (Company ID 0xCEBD, unregistered).
//!
//! 0xCEBD is not a SIG-assigned Company ID; this vendor squats on it. Frames
//! carry a 6-byte identifier that is not the advertising address (those frames
//! use a rotating RPA, so this is a stable handle that survives the rotation),
//! three battery percentages for the left bud, right bud and case (0xFF where a
//! bud is out of the case and unreported), two state bytes, and the product name
//! as UTF-8. Reverse-engineered from captures.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// "Ola Friends" earbuds — manufacturer data (Company ID 0xCEBD, unregistered).
pub(super) struct OlaFriends;
impl super::VendorDecoder for OlaFriends {
    fn company_ids(&self) -> &'static [u16] { &[0xCEBD] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 11 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Ola Friends: id=");
        super::write_mac_be(&mut s, &body[0..6]);
        let _ = write!(s, " battery L=");
        write_batt(&mut s, body[6]);
        let _ = write!(s, " R=");
        write_batt(&mut s, body[7]);
        let _ = write!(s, " case=");
        write_batt(&mut s, body[8]);
        let _ = write!(s, " state=0x{:02X}{:02X}", body[9], body[10]);
        emit(s);
        super::emit_oui_vendor(&body[0..6]);
        // The name runs to the end of the frame and is cut off at the AD-structure
        // length limit, so print whatever arrived.
        if body.len() > 11 {
            let mut s: LogStr = LogStr::new();
            let _ = write!(s, "    Ola Friends: name=\"");
            match core::str::from_utf8(&body[11..]) {
                Ok(n) => { let _ = write!(s, "{}\"", n); emit(s); }
                Err(e) => {
                    // A multi-byte character split by the length limit leaves an
                    // incomplete tail; print the part that decodes.
                    let vu = e.valid_up_to();
                    if let Ok(n) = core::str::from_utf8(&body[11..11 + vu]) {
                        let _ = write!(s, "{}...\"", n);
                    }
                    emit(s);
                }
            }
        }
    }
}

/// Battery percentage, or `?` for the 0xFF "unreported" value.
fn write_batt(s: &mut LogStr, v: u8) {
    if v == 0xFF {
        let _ = write!(s, "?");
    } else {
        let _ = write!(s, "{}%", v);
    }
}
