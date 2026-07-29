//! MOTIVE Technologies service data (UUID 0xFC70).
//!
//! Motive builds commercial-fleet telematics (vehicle gateways and dashcams).
//! Its frames are the largest in the capture at 113 bytes, which needs extended
//! advertising to carry. The opening `00 15 06 13 08` header and a 4-byte
//! counter that recurs near the end of the frame are stable across sightings;
//! everything between them changes on every frame and is ciphertext. The header
//! and counter are decoded and the body is kept as hex.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// MOTIVE TECHNOLOGIES, INC. — service data (UUID 0xFC70).
pub(super) struct Motive;
impl super::VendorDecoder for Motive {
    fn service_uuids(&self) -> &'static [u16] { &[0xFC70] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 5 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Motive fleet telematics: hdr=");
        write_hex(&mut s, &body[..5]);
        let _ = write!(s, " encrypted len={}", body.len() - 5);
        emit(s);
        hexdump(&body[5..], ctx.base + 5, 6);
    }
}
