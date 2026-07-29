//! GoPro manufacturer data (Company ID 0x02F2) and service data (UUID 0xFEA6).
//!
//! Open GoPro documents the GATT control API but not the advertising payload, so
//! the layouts below are read off captures. Both frames a camera emits are useful:
//!
//! * **Service data 0xFEA6** — 8 bytes: a 4-byte camera identifier followed by the
//!   **camera's 4-digit serial suffix in ASCII**. That suffix is exactly what the
//!   camera puts in its advertised name (`GoPro 3381` ↔ service data `…33 33 38 31`),
//!   so it identifies the unit even when the name AD is absent or truncated.
//! * **Manufacturer data 0x02F2** — 12 bytes opening with a constant `02 00 3E 23`
//!   header; the remaining 8 bytes are a per-camera value (seen as ASCII digits on
//!   one camera, binary on another), reported as an opaque id.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// GoPro, Inc. — manufacturer data (0x02F2) and service data (0xFEA6).
pub(super) struct GoPro;
impl super::VendorDecoder for GoPro {
    fn company_ids(&self) -> &'static [u16] { &[0x02F2] }
    fn service_uuids(&self) -> &'static [u16] { &[0xFEA6] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        match ctx.kind {
            super::FrameKind::Service => Self::decode_service(ctx, body),
            super::FrameKind::Mfg => Self::decode_mfg(ctx, body),
        }
    }
}

impl GoPro {
    /// Service data 0xFEA6: `[id×4][serial-suffix ASCII×4]`.
    fn decode_service(ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 8 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    GoPro camera: id=");
        write_hex(&mut s, &body[0..4]);
        // The trailing four bytes are the printable serial suffix — the same digits
        // the camera shows in its name and on the "GoPro <NNNN>" pairing screen.
        let tail = &body[4..8];
        if tail.iter().all(|&b| b.is_ascii_alphanumeric()) {
            let _ = write!(s, " serial=");
            for &b in tail {
                let _ = write!(s, "{}", b as char);
            }
        } else {
            let _ = write!(s, " tail=");
            write_hex(&mut s, tail);
        }
        emit(s);
    }

    /// Manufacturer data 0x02F2: constant `02 00 3E 23` header + 8 opaque bytes.
    fn decode_mfg(ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 4 || body[0] != 0x02 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    GoPro (unofficial): hdr=");
        write_hex(&mut s, &body[0..4]);
        if body.len() > 4 {
            let rest = &body[4..];
            let _ = write!(s, " id=");
            write_hex(&mut s, rest);
            if rest.iter().all(|&b| b.is_ascii_graphic()) {
                let _ = write!(s, " (\"");
                for &b in rest {
                    let _ = write!(s, "{}", b as char);
                }
                let _ = write!(s, "\")");
            }
        }
        emit(s);
    }
}
