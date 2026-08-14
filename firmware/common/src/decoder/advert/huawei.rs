//! Huawei device discovery (service `0xFDEE` and Company ID `0x027D`).
//!
//! Used by Huawei "HiLink" / HarmonyOS Nearby / Wear ecosystem device
//! discovery. Both UUIDs are SIG-confirmed to Huawei Technologies Co., Ltd.:
//! * 0x027D — `company_identifiers.yaml`
//! * 0xFDEE — `member_uuids.yaml`
//!
//! **No public byte-level RE is available** for either format. Searches
//! across theengs/decoder, reelyactive advlib-ble-manufacturers, Nordic
//! bluetooth-numbers-database, and Github code search returned nothing
//! actionable. (Huawei's "NearLink" / 星闪 developer docs describe a
//! *separate radio protocol*, not BLE.)
//!
//! Both frames begin with a type/frame byte followed by rotating, opaque
//! identifier bytes. We surface only the leading byte and the length so a
//! Huawei-emitting device can be counted / classified, but do not invent
//! field meanings for the rest.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Huawei — service data (UUID 0xFDEE) and manufacturer data (Company ID 0x027D):
/// HiLink / HarmonyOS discovery. Layout past the leading byte is undocumented.
pub(super) struct Huawei;
impl super::VendorDecoder for Huawei {
    fn company_ids(&self) -> &'static [u16] { &[0x027D] }
    fn service_uuids(&self) -> &'static [u16] { &[0xFDEE] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let tag = match ctx.kind {
            super::FrameKind::Mfg => "Huawei 0x027D (no public RE)",
            super::FrameKind::Service => "Huawei 0xFDEE (no public RE)",
        };
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    {}: type=0x{:02X} data len={}",
            tag, body[0], body.len() - 1);
        emit(s);
        hexdump(&body[1..], ctx.base + 1, 6);
    }
}
