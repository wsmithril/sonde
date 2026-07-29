//! OPPO / OnePlus cross-device service data (UUID 0x686B).
//!
//! 0x686B is not a SIG-assigned UUID. OPPO's cross-device discovery ("O+ 互传")
//! advertises a 6-byte identifier followed by AD type 0x08 (Shortened Local
//! Name) and the handset's model name as UTF-8 — "OPPO Find X8", "一加13" and
//! similar. The name is plaintext under a rotating advertising address, so it
//! is the useful field. Reverse-engineered from captures.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// OPPO / OnePlus cross-device discovery — service data (UUID 0x686B).
pub(super) struct Oplus;
impl super::VendorDecoder for Oplus {
    fn service_uuids(&self) -> &'static [u16] { &[0x686B] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 7 || body[6] != 0x08 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    OPPO/OnePlus cross-device: id=");
        super::write_mac_be(&mut s, &body[0..6]);
        emit(s);
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    OPPO/OnePlus cross-device: name=\"");
        match core::str::from_utf8(&body[7..]) {
            Ok(n) => { let _ = write!(s, "{}\"", n); }
            Err(e) => {
                // The name is cut off at the AD-structure length limit, which can
                // split a multi-byte character; print the part that decodes.
                let vu = e.valid_up_to();
                if let Ok(n) = core::str::from_utf8(&body[7..7 + vu]) {
                    let _ = write!(s, "{}...\"", n);
                }
            }
        }
        emit(s);
    }
}
