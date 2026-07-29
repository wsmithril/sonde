//! PKOC — Public Key Open Credential (service UUID 0xFFF0).
//!
//! An open access-control credential standard (PSIA / PKOC Alliance): a phone or
//! card badge proves possession of a P-256 private key to a reader, replacing the
//! cloneable fixed IDs of legacy 125 kHz / MIFARE credentials.
//!
//! The advertisement is deliberately thin — the credential's public key is
//! exchanged over GATT after connecting, not broadcast. What is advertised is the
//! service UUID plus a short service-data body:
//!
//! ```text
//! [0]    protocol version (0x01 for PKOC v1)
//! [1..]  optional reader/credential hint bytes (implementation-defined)
//! ```
//!
//! Seeing 0xFFF0 in a capture means an **access-control credential or reader** is
//! present — worth flagging in a survey even though the payload itself is short.
//! Note 0xFFF0 is also used by some generic/no-name modules as a catch-all custom
//! service, so the label is reported as a likely-PKOC hint rather than a certainty.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// PKOC access credential — service data (UUID 0xFFF0).
pub(super) struct Pkoc;
impl super::VendorDecoder for Pkoc {
    fn service_uuids(&self) -> &'static [u16] { &[0xFFF0] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    PKOC? (access credential, UUID 0xFFF0)");
        if let Some(&ver) = body.first() {
            let _ = write!(s, ": ver=0x{:02X}", ver);
            if ver == 0x01 {
                let _ = write!(s, " (PKOC v1)");
            }
            if body.len() > 1 {
                let _ = write!(s, " +{}B", body.len() - 1);
            }
        } else {
            let _ = write!(s, ": no service data (UUID-only advertisement)");
        }
        emit(s);
        if body.len() > 1 {
            hexdump(&body[1..], ctx.base + 1, 6);
        }
    }
}
