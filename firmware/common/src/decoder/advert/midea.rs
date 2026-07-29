//! Midea manufacturer data (Company ID 0x06A8) and service data (UUID 0xFD25).
//!
//! Midea appliances (A/C, fans, kitchen) advertise a manufacturer frame with the
//! layout `[01][SN14][01 03 00 32][MAC6 reversed][00]` (midea-ble-go
//! `docs/protocol.md`): a fixed 0x01 frame byte, a 14-char ASCII short serial,
//! a fixed marker, and — in the full 26-byte form — the appliance's real MAC in
//! reverse. Most units only broadcast the 15-byte `[01][SN14]` short form. The
//! SN and MAC are the HKDF input for the appliance's control-channel root key,
//! so they are the identity worth logging. The `0xFD25` service frame carries
//! binary pairing state with no public layout.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Midea — manufacturer data (Company ID 0x06A8) and service data (UUID 0xFD25).
pub(super) struct Midea;
impl super::VendorDecoder for Midea {
    fn company_ids(&self) -> &'static [u16] { &[0x06A8] }
    fn service_uuids(&self) -> &'static [u16] { &[0xFD25] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        match ctx.kind {
            super::FrameKind::Mfg => {
                let mut s: LogStr = LogStr::new();
                let _ = write!(s, "    Midea: type=0x{:02X}", body[0]);
                // The 14-char ASCII SN follows the frame byte; short frames stop
                // there, full (>=25B) frames add a fixed marker and the real MAC
                // (bytes 19..25, reversed).
                let sn = if body.len() >= 15 { &body[1..15] } else { &body[1..] };
                if !sn.is_empty() && sn.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                    let _ = write!(s, " sn=\"");
                    for &b in sn { let _ = s.push(b as char); }
                    let _ = write!(s, "\"");
                    // Full frame: recover the appliance's real MAC from the tail.
                    if body.len() >= 25 && body[15] == 0x01 {
                        let m = &body[19..25];
                        let _ = write!(s, " mac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            m[5], m[4], m[3], m[2], m[1], m[0]);
                    }
                    emit(s);
                } else {
                    emit(s);
                    hexdump(&body[1..], ctx.base + 1, 6);
                }
            }
            super::FrameKind::Service => {
                let mut s: LogStr = LogStr::new();
                let _ = write!(s, "    Midea 0xFD25: len={}", body.len());
                emit(s);
                hexdump(body, ctx.base, 6);
            }
        }
    }
}
