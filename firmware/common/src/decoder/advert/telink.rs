//! Telink Semiconductor manufacturer data (Company ID 0x0211).
//!
//! 0x0211 is the CID of the BLE-SoC chipmaker, not of any particular OEM. The
//! Telink BLE SDK populates the mfg-data with the chipset vendor's CID by
//! default, and OEMs that don't override it (notably **Honor** phones and
//! wearables — Honor's own CID is 0x09C6 but the Telink SDK's CID leaks
//! through on-air) show up here. This is documented in
//! github.com/bensmith83/adwatch/blob/main/docs/protocols/honor-ble.md.
//!
//! Two frame variants are observed in the wild:
//!
//! * **short** — 8 bytes: `11 22` TLV prefix, then a 4-byte rotating token.
//! * **long** — 35 bytes: adds a nested `11 02 <token>` echo, a second `25`
//!   TLV type, a 4-byte state quad (`00 01 8B/99 00`), a 5-byte constant
//!   token, a 1-byte tail flag, then the Telink SDK's default fill
//!   `06 07 08 09 0A 0B 0C 0D 0E 0F`. That trailing sequential run is a
//!   strong fingerprint of an un-customised Telink SDK build.
//!
//! Field semantics past the tokens (state quad, tail flag) are not confirmed.
//! When the SDK-fill signature is present we hint at Honor; other Telink-chip
//! devices could share the shape, so the label is a hint not a positive ID.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Telink SDK default-fill signature — the trailing 10 bytes of a "long" frame.
const TELINK_SDK_FILL: &[u8; 10] =
    &[0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

/// Telink Semiconductor — manufacturer data (Company ID 0x0211).
pub(super) struct Telink;
impl super::VendorDecoder for Telink {
    fn company_ids(&self) -> &'static [u16] { &[0x0211] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        let mut s: LogStr = LogStr::new();

        // Frame-shape classifier: the `11 22` TLV prefix + trailing SDK-fill
        // pattern is the Honor-Telink long variant. The short variant is the
        // same 4-byte prefix without any tail.
        let long = body.len() >= 25
            && body[0] == 0x11 && body[1] == 0x22
            && body.ends_with(TELINK_SDK_FILL);
        let short = body.len() == 6
            && body[0] == 0x11 && body[1] == 0x22;

        if long {
            let _ = write!(s, "    Telink SDK / Honor? (long): token=");
            write_hex(&mut s, &body[2..6]);
            if body.len() >= 12 {
                let _ = write!(s, " nested=");
                write_hex(&mut s, &body[8..12]);
            }
            if body.len() >= 17 {
                let _ = write!(s, " state=");
                write_hex(&mut s, &body[13..17]);
            }
            if body.len() >= 25 {
                let _ = write!(s, " tail-flag=0x{:02X}", body[22]);
            }
            emit(s);
        } else if short {
            let _ = write!(s, "    Telink SDK / Honor? (short): token=");
            write_hex(&mut s, &body[2..6]);
            emit(s);
        } else {
            let _ = write!(s, "    Telink SoC (unrecognised): len={}", body.len());
            emit(s);
        }
        hexdump(body, ctx.base, 6);
    }
}
