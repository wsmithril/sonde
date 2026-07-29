//! ASHA (Audio Streaming for Hearing Aids) service data (UUID 0xFDF0 and 0xFCFE).
//!
//! The Google ASHA spec defines a 17-byte advertisement payload on UUID 0xFDF0.
//! Sonova (Phonak/Sennheiser/etc.) uses UUID 0xFCFE with a 19-byte variant.
//! Both carry the same core fields:
//!
//! ```text
//! [0]    ProtocolVersion  — 0x01 for ASHA v1
//! [1]    Capabilities     — bit0=side(0=L,1=R), bit1=CSIP member, bit2=LE audio capable
//! [2–9]  HiSyncId         — 8-byte identifier: shared between paired L/R devices
//!                           (top 4 bytes stable across models, bottom 4 differ per side)
//! [10–11] FeatureMap      — bit0=CSIS, other bits reserved
//! [12–13] RenderingDelay  — audio rendering latency in ms (LE u16)
//! [14–15] ReservedForFuture
//! [16]   CodecBitMap       — bit0=G.722 at 16kHz, bit1=G.722 at 24kHz
//! ```
//!
//! ASHA spec: https://source.android.com/devices/accessories/headset/asha

use core::fmt::Write;

use super::{emit, LogStr};

/// Sonova Consumer Hearing / ASHA — service data (UUID 0xFCFE and 0xFDF0).
///
/// 0xFDF0 follows the Google ASHA spec exactly. 0xFCFE is a Sonova-proprietary
/// UUID that overlaps structurally but adds vendor fields; we decode the common
/// core and label the tail as opaque.
pub(super) struct Asha;
impl super::VendorDecoder for Asha {
    fn service_uuids(&self) -> &'static [u16] { &[0xFCFE, 0xFDF0] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        let (vendor, asha_strict) = if ctx.key == 0xFCFE {
            ("Sonova 0xFCFE", false) // Sonova proprietary; share ASHA structure
        } else {
            ("ASHA 0xFDF0", true)
        };

        if body.len() < 17 {
            let mut s: LogStr = LogStr::new();
            let _ = write!(s, "    {} (len={} too short for full decode)", vendor, body.len());
            emit(s);
            return;
        }

        // ASHA spec layout (byte offsets):
        //   [0]    ProtocolVersion
        //   [1]    Capabilities: bit0=side(0=L,1=R), bit1=CSIP, bit2=LE-audio
        //   [2–9]  HiSyncId (8 bytes LE): shared across paired L+R; same high-4 = stereo pair
        //  [10–11] FeatureMap
        //  [12–13] RenderingDelay (ms, LE u16)
        //  [14–15] reserved
        //  [16]    CodecBitMap: bit0=G.722@16kHz, bit1=G.722@24kHz
        let version = body[0];
        let caps    = body[1];
        let side    = if caps & 0x01 != 0 { "R" } else { "L" };
        let csip    = caps & 0x02 != 0;
        let le_aud  = caps & 0x04 != 0;
        let hi_hi   = u32::from_le_bytes([body[2], body[3], body[4], body[5]]);
        let hi_lo   = u32::from_le_bytes([body[6], body[7], body[8], body[9]]);
        let feat    = u16::from_le_bytes([body[10], body[11]]);
        let delay   = u16::from_le_bytes([body[12], body[13]]);
        let codec_b = body[16];
        let codec   = match codec_b & 0x03 {
            0x03 => "G.722@16+24kHz",
            0x02 => "G.722@24kHz",
            0x01 => "G.722@16kHz",
            _    => "?",
        };

        let mut s: LogStr = LogStr::new();
        let _ = write!(s,
            "    {} v{}: side={} delay={}ms codec={} feat=0x{:04X} sync={:08X}/{:08X}",
            vendor, version, side, delay, codec, feat, hi_hi, hi_lo,
        );
        if csip || le_aud {
            let _ = write!(s, " [");
            if csip   { let _ = write!(s, "CSIP"); }
            if le_aud { let _ = write!(s, "{}LE-audio", if csip { " " } else { "" }); }
            let _ = write!(s, "]");
        }
        if !asha_strict && body.len() > 17 {
            let _ = write!(s, " +{}B vendor", body.len() - 17);
        }
        emit(s);
    }
}
