//! Midea manufacturer data (Company ID 0x06A8) and service data (UUID 0xFD25).
//!
//! Midea appliances (A/C, fans, kitchen) advertise a manufacturer frame that
//! begins with a type byte (0x01 observed) followed by an ASCII serial/SN-style
//! identifier used for app pairing. The `0xFD25` service frame carries binary
//! pairing state with no public layout.

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
                // type 0x01 frames carry an ASCII serial/SN in the remaining bytes.
                let id = &body[1..];
                if !id.is_empty() && id.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                    let _ = write!(s, " sn=\"");
                    for &b in id { let _ = s.push(b as char); }
                    let _ = write!(s, "\"");
                    emit(s);
                } else {
                    emit(s);
                    hexdump(id, ctx.base + 1, 6);
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
