//! OPPO / OnePlus / Realme "Heytap" manufacturer data.
//!
//! OPPO, OnePlus, and Realme share the same cross-device advertising stack
//! (marketed as OPPO Cross-device / Heytap / OnePlus Spirit). All three brands
//! emit mfg-data with an identical 8-byte header `AF 30 2B 14 88 00 4C 26`,
//! then ~5 state bytes and a ~6-byte rotating tail (~19–20 bytes total). The
//! CID identifies the sub-brand:
//!
//! * 0x079A → GuangDong Oppo Mobile Telecommunications
//! * 0x072F → OnePlus Electronics (Shenzhen)
//! * 0x08A4 → Realme Chongqing Mobile Telecommunications
//!
//! The payload bytes past the header are undocumented — no public source
//! describes them (searches across OPPO/ColorOS/HeyTap Spirit developer docs,
//! reelyactive/advlib-ble-manufacturers, Nordic bluetooth-numbers-database,
//! and general RE forums returned nothing). Companion service data on UUID
//! 0x686B (decoded in [`super::oplus`]) carries the plaintext marketing model.
//!
//! Frame-header signature confirmed in
//! github.com/bensmith83/adwatch/blob/main/docs/protocols/oneplus.md and
//! github.com/bensmith83/adwatch/blob/main/docs/protocols/oppo.md.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Heytap 8-byte header shared across OPPO / OnePlus / Realme mfg-data.
const HEYTAP_HEADER: &[u8; 8] = &[0xAF, 0x30, 0x2B, 0x14, 0x88, 0x00, 0x4C, 0x26];

/// OPPO — manufacturer data (Company ID 0x079A).
pub(super) struct Oppo;
impl super::VendorDecoder for Oppo {
    fn company_ids(&self) -> &'static [u16] { &[0x079A] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        decode_heytap(ctx, body, "OPPO");
    }
}

/// OnePlus — manufacturer data (Company ID 0x072F). Same 8-byte Heytap header
/// as OPPO / Realme; brand is disambiguated by CID.
pub(super) struct OnePlus;
impl super::VendorDecoder for OnePlus {
    fn company_ids(&self) -> &'static [u16] { &[0x072F] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        decode_heytap(ctx, body, "OnePlus");
    }
}

/// Realme — manufacturer data (Company ID 0x08A4). Same 8-byte Heytap header
/// as OPPO / OnePlus; brand is disambiguated by CID.
pub(super) struct Realme;
impl super::VendorDecoder for Realme {
    fn company_ids(&self) -> &'static [u16] { &[0x08A4] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        decode_heytap(ctx, body, "Realme");
    }
}

fn decode_heytap(ctx: &super::DecodeCtx, body: &[u8], brand: &str) {
    if body.is_empty() { return; }
    // The Heytap header is stable across all three brands; state and tail
    // bytes past it are undocumented, so surface the header match as the
    // recognised structure and dump the rest.
    if body.len() >= HEYTAP_HEADER.len() && &body[..HEYTAP_HEADER.len()] == HEYTAP_HEADER {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    {} Heytap: header=", brand);
        write_hex(&mut s, HEYTAP_HEADER);
        let _ = write!(s, " tail-len={}", body.len() - HEYTAP_HEADER.len());
        emit(s);
        hexdump(&body[HEYTAP_HEADER.len()..], ctx.base + HEYTAP_HEADER.len(), 6);
        return;
    }
    // Non-Heytap frames on these CIDs: the current firmware sees rare short
    // variants that don't start with the shared header. No public RE.
    let mut s: LogStr = LogStr::new();
    let _ = write!(s, "    {} (fast-connect): frame=0x{:02X} len={}",
        brand, body[0], body.len());
    emit(s);
    hexdump(body, ctx.base, 6);
}
