//! Garmin manufacturer data (Company ID 0x0087).
//!
//! Garmin watches and cycling computers emit a minimal **2-byte** proximity
//! beacon — by far the shortest manufacturer frame in a typical capture, and the
//! reason a room full of Garmin devices produces high packet volume but very
//! little information. No public spec; read off captures:
//!
//! ```text
//! [0] flags/state — high nibble is near-constant (0x1_), low nibble varies
//! [1] product/protocol tag — 0xA1 on the overwhelming majority of frames
//! ```
//!
//! Across 4,929 clean frames from 65 distinct addresses in one capture, 4,893
//! were exactly `10 A1`; the remainder differ in only a nibble or two. There is
//! no serial, model, or battery here — the device identity lives in the
//! advertising address and (when present) the scan-response name, so this decoder
//! reports the two bytes and stops rather than inventing structure.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Garmin International, Inc. — manufacturer data (Company ID 0x0087).
pub(super) struct Garmin;
impl super::VendorDecoder for Garmin {
    fn company_ids(&self) -> &'static [u16] { &[0x0087] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 2 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Garmin (unofficial): state=0x{:02X} tag=0x{:02X}", body[0], body[1]);
        // 0xA1 is the tag on essentially every observed frame; flag anything else
        // so a genuinely different Garmin product stands out in a capture.
        if body[1] != 0xA1 {
            let _ = write!(s, " (non-standard tag)");
        }
        if body.len() > 2 {
            let _ = write!(s, " +{}B", body.len() - 2);
        }
        emit(s);
        if body.len() > 2 {
            hexdump(&body[2..], ctx.base + 2, 6);
        }
    }
}
