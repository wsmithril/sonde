//! Google service-data formats other than Fast Pair (which is 0xFE2C).
//!
//! `0xFCF1` is a Google-owned SIG member service used by Google Play Services
//! (Nearby / cross-device). Its frame layout is **not publicly documented**:
//! every payload observed begins with a frame/version byte (0x04) followed by
//! ~20 bytes of high-entropy, rotating data — an encrypted ephemeral identifier.
//! There is nothing further to parse, so we surface only the frame byte and
//! label it correctly (it would otherwise show as an opaque "Google LLC" blob).

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Google — Nearby service data: Play Services (UUID 0xFCF1) and cross-device
/// (UUID 0xFEF3); dispatched by UUID.
pub(super) struct Google;
impl super::VendorDecoder for Google {
    fn service_uuids(&self) -> &'static [u16] { &[0xFCF1, 0xFEF3] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        match ctx.key {
            0xFEF3 => Self::decode_fef3(body, ctx.base),
            _ => Self::decode_fcf1(body, ctx.base),
        }
    }
}

impl Google {
    fn decode_fcf1(f: &[u8], base: usize) {
        if f.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s,
            "    Google 0xFCF1 (Play Services, undocumented): frame=0x{:02X} rotating len={}",
            f[0], f.len() - 1);
        emit(s);
        hexdump(&f[1..], base + 1, 6);
    }

    /// `0xFEF3` is another Google-owned SIG member service (Nearby / cross-device).
    /// Like 0xFCF1 it carries a frame byte followed by rotating encrypted identifier
    /// bytes with no public layout, so we label it and surface the frame byte only.
    fn decode_fef3(f: &[u8], base: usize) {
        if f.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s,
            "    Google 0xFEF3 (Nearby, undocumented): frame=0x{:02X} rotating len={}",
            f[0], f.len() - 1);
        emit(s);
        hexdump(&f[1..], base + 1, 6);
    }
}
