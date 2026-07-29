//! mobike (Meituan Bike) manufacturer data (Company ID 0x04B3).
//!
//! Shared-bike locks advertise a 16-byte frame that opens with version 0x02, a
//! one-byte level, and the lock's own 6-byte address in display (MSB-first)
//! order — verified against the advertiser address of the same packet, so the
//! frame republishes the identity that the `rand-static` address already carries.
//! The trailing bytes hold a fixed 0x81 marker, two state bytes, a two-byte
//! counter, and a constant `03 00 00` tail; those are labelled and left as hex.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// mobike (Hong Kong) Limited — manufacturer data (Company ID 0x04B3).
pub(super) struct Mobike;
impl super::VendorDecoder for Mobike {
    fn company_ids(&self) -> &'static [u16] { &[0x04B3] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 8 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    mobike: v{} level={} addr=", body[0], body[1]);
        super::write_mac_be(&mut s, &body[2..8]);
        emit(s);
        super::emit_oui_vendor(&body[2..8]);
        if body.len() > 8 {
            let mut s: LogStr = LogStr::new();
            let _ = write!(s, "    mobike: state=");
            write_hex(&mut s, &body[8..]);
            emit(s);
        }
    }
}
