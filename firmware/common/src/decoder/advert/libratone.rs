//! Libratone A/S manufacturer data (Company ID 0x034B).
//!
//! Libratone (Danish wireless-speaker brand) has no published BLE advertising
//! spec, and no public RE covers the on-air layout. Searches across
//! theengs/decoder, reelyactive advlib-ble-manufacturers, Nordic
//! bluetooth-numbers-database, and Github code search returned nothing
//! actionable for 0x034B. Vendor attribution is confirmed against the SIG
//! canonical CID registry:
//! bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/
//! company_identifiers/company_identifiers.yaml
//!
//! We label the vendor and dump the raw body so ASCII strings (firmware
//! versions, model hints) that may be embedded in the payload show up in the
//! hexdump gutter without fabricated field decoding.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Libratone A/S — manufacturer data (Company ID 0x034B).
pub(super) struct Libratone;
impl super::VendorDecoder for Libratone {
    fn company_ids(&self) -> &'static [u16] { &[0x034B] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Libratone (no public RE): len={}", body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}
