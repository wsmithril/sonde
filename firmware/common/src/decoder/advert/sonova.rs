//! Sonova Consumer Hearing GmbH manufacturer data (Company ID 0x0BA3).
//!
//! Sonova (Phonak, Sennheiser hearing aids, etc.) uses two advertising payloads:
//!   • Manufacturer-specific data (0x0BA3): observed as 17 bytes — proprietary
//!     device identifier / link state. No public spec. Byte 0 is a status/state
//!     nibble; the rest appears to be a rotating device credential.
//!   • Service data UUID 0xFCFE: ASHA hearing-aid profile (decoded by `asha.rs`).
//!
//! This decoder handles only the 0x0BA3 manufacturer frame. The ASHA service
//! data is decoded by [`super::asha::Asha`].
//!
//! The device name (seen in the Name AD field) is the hearing-aid brand/model:
//! "MOMENTUM TW 4" (Sennheiser TWS, Sonova OEM), "Phonak Audéo", etc. We
//! surface the opaque payload length so a capture post-analysis can spot changes.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Sonova Consumer Hearing GmbH — manufacturer data (Company ID 0x0BA3).
///
/// Advertised by Sonova-platform hearing aids and Sennheiser-branded TWS earbuds
/// (Sennheiser is wholly owned by Sonova). The 17-byte body is proprietary;
/// byte 0 contains a connection-state nibble (0x01 = advertising, 0x02 = bonded).
pub(super) struct Sonova;
impl super::VendorDecoder for Sonova {
    fn company_ids(&self) -> &'static [u16] { &[0x0BA3] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let state = body[0];
        let state_str = match state {
            0x01 => "advertising",
            0x02 => "bonded",
            0x03 => "reconnecting",
            _    => "?",
        };
        let mut s: LogStr = LogStr::new();
        let _ = write!(s,
            "    Sonova (hearing/TWS): state=0x{:02X}({}) payload_len={}",
            state, state_str, body.len()
        );
        emit(s);
        // Remaining bytes: rotating device credential — no public layout.
        if body.len() > 1 {
            hexdump(&body[1..], ctx.base + 1, 6);
        }
    }
}
