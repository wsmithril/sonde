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

    /// `0xFEF3` is Google's "Copresence" service — the Nearby Connections BLE
    /// advertisement (Nearby Share / Quick Share). The first byte is a plaintext
    /// header: `version(3) | socket_version(3) | fast_advert(1) | second_profile(1)`
    /// (google/nearby `ble_advertisement.h`). The rest is the service-ID hash,
    /// endpoint and — only when the sender is in "visible to everyone" mode — a
    /// plaintext device name; in contact/hidden mode it is an encrypted metadata
    /// blob, so it stays as the rotating hex dump.
    fn decode_fef3(f: &[u8], base: usize) {
        if f.is_empty() { return; }
        let h = f[0];
        let mut s: LogStr = LogStr::new();
        let _ = write!(s,
            "    Google 0xFEF3 (Nearby Connections): v{} sockv{} fast={} 2nd-profile={} rotating len={}",
            h >> 5, (h >> 2) & 0x07, (h >> 1) & 0x01, h & 0x01, f.len() - 1);
        emit(s);
        hexdump(&f[1..], base + 1, 6);
    }
}
