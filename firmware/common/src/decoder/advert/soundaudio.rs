//! Sounding Audio manufacturer data (Company ID 0x0E0B).
//!
//! Observed frames are 15 bytes: a fixed `0A 0C` header, seven state bytes, and
//! the advertiser's own 6-byte address in display order (verified against the
//! packet header of the same frame). Reverse-engineered from captures.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Sounding Audio Industrial Ltd. — manufacturer data (Company ID 0x0E0B).
pub(super) struct SoundAudio;
impl super::VendorDecoder for SoundAudio {
    fn company_ids(&self) -> &'static [u16] { &[0x0E0B] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 15 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Sounding Audio (unofficial): state=");
        write_hex(&mut s, &body[2..9]);
        let _ = write!(s, " addr=");
        super::write_mac_be(&mut s, &body[9..15]);
        emit(s);
        super::emit_oui_vendor(&body[9..15]);
    }
}
