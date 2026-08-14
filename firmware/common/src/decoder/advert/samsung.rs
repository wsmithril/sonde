//! Samsung manufacturer data (Company ID 0x0075).
//!
//! Used by Galaxy phones/wearables and Galaxy Buds. Two families are covered
//! here; other subtypes (SmartThings-Find, Continuity-style device advertising)
//! ride SIG-registered service UUIDs, not this CID.
//!
//! Frame families keyed on the first body byte:
//!
//! * `0x42` **EasySetup Buds** — 27-byte payload. Bytes 4..14 are a fixed
//!   prefix `15 03 21 01 09`, then a 24-bit model / color ID split across
//!   `body[10]`, `body[11]`, `body[13]` (`body[12] == 0x01` static), then a
//!   fixed suffix `06 3C 94 8E 00 00 00 00 C7 00`. Model-ID table below.
//!
//! * `0x01` **EasySetup Watch** — 11-byte payload. Fixed prefix
//!   `00 02 00 01 01 FF 00 00 43`, then an 8-bit model ID at `body[10]`.
//!
//! Both formats and the model-ID tables were reverse-engineered by
//! @Spooks4576 and reproduced in the Flipper "ble_spam" easysetup protocol:
//! github.com/xMasterX/all-the-plugins/blob/main/base_pack/ble_spam/protocols/easysetup.c

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Samsung Electronics — manufacturer data (Company ID 0x0075).
pub(super) struct Samsung;
impl super::VendorDecoder for Samsung {
    fn company_ids(&self) -> &'static [u16] { &[0x0075] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        match body[0] {
            0x42 => Self::decode_buds(ctx, body),
            0x01 => Self::decode_watch(ctx, body),
            _    => Self::decode_generic(ctx, body),
        }
    }
}

impl Samsung {
    /// EasySetup Buds frame: extract the 24-bit model / color ID from
    /// `body[10] << 16 | body[11] << 8 | body[13]` and look it up in the
    /// @Spooks4576 catalog.
    fn decode_buds(ctx: &super::DecodeCtx, body: &[u8]) {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Samsung EasySetup Buds: len={}", body.len());
        if body.len() >= 14 {
            let model = ((body[10] as u32) << 16) | ((body[11] as u32) << 8) | (body[13] as u32);
            let _ = write!(s, " model=0x{:06X}", model);
            if let Some(name) = buds_name(model) {
                let _ = write!(s, " ({})", name);
            }
        }
        emit(s);
        hexdump(body, ctx.base, 6);
    }

    /// EasySetup Watch frame: 8-bit model ID at body[10].
    fn decode_watch(ctx: &super::DecodeCtx, body: &[u8]) {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Samsung EasySetup Watch: len={}", body.len());
        if body.len() >= 11 {
            let model = body[10];
            let _ = write!(s, " model=0x{:02X}", model);
            if let Some(name) = watch_name(model) {
                let _ = write!(s, " ({})", name);
            }
        }
        emit(s);
        hexdump(body, ctx.base, 6);
    }

    /// Any other leading byte: labelled but not decoded.
    fn decode_generic(ctx: &super::DecodeCtx, body: &[u8]) {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Samsung (unrecognised): type=0x{:02X} len={}",
            body[0], body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}

/// Galaxy Buds model / color IDs (24-bit). Names as documented in the
/// @Spooks4576 EasySetup catalog; "Fallback" IDs are the generic types used
/// when no specific SKU pattern is emulated.
fn buds_name(id: u32) -> Option<&'static str> {
    Some(match id {
        0xEE7A0C => "Fallback Buds",
        0x9D1700 => "Fallback Dots",
        0x39EA48 => "Light Purple Buds2",
        0xA7C62C => "Bluish Silver Buds2",
        0x850116 => "Black Buds Live",
        0x3D8F41 => "Gray & Black Buds2",
        0x3B6D02 => "Bluish Chrome Buds2",
        0xAE063C => "Gray Beige Buds2",
        0xB8B905 => "Pure White Buds",
        0xEAAA17 => "Pure White Buds2",
        0xD30704 => "Black Buds",
        0x9DB006 => "French Flag Buds",
        0x101F1A => "Dark Purple Buds Live",
        0x859608 => "Dark Blue Buds",
        0x8E4503 => "Pink Buds",
        0x2C6740 => "White & Black Buds2",
        0x3F6718 => "Bronze Buds Live",
        0x42C519 => "Red Buds Live",
        0xAE073A => "Black & White Buds2",
        0x011716 => "Sleek Black Buds2",
        _        => return None,
    })
}

/// Galaxy Watch model IDs (8-bit).
fn watch_name(id: u8) -> Option<&'static str> {
    Some(match id {
        0x1A => "Fallback Watch",
        0x01 => "White Watch4 Classic 44mm",
        0x02 => "Black Watch4 Classic 40mm",
        0x03 => "White Watch4 Classic 40mm",
        0x04 => "Black Watch4 44mm",
        0x05 => "Silver Watch4 44mm",
        0x06 => "Green Watch4 44mm",
        0x07 => "Black Watch4 40mm",
        0x08 => "White Watch4 40mm",
        0x09 => "Gold Watch4 40mm",
        0x0A => "French Watch4",
        0x0B => "French Watch4 Classic",
        0x0C => "Fox Watch5 44mm",
        0x11 => "Black Watch5 44mm",
        0x12 => "Sapphire Watch5 44mm",
        0x13 => "Purpleish Watch5 40mm",
        0x14 => "Gold Watch5 40mm",
        0x15 => "Black Watch5 Pro 45mm",
        0x16 => "Gray Watch5 Pro 45mm",
        0x17 => "White Watch5 44mm",
        0x18 => "White & Black Watch5",
        0x1B => "Black Watch6 Pink 40mm",
        0x1C => "Gold Watch6 Gold 40mm",
        0x1D => "Silver Watch6 Cyan 44mm",
        0x1E => "Black Watch6 Classic 43mm",
        0x20 => "Green Watch6 Classic 43mm",
        0xE4 => "Black Watch5 Golf Edition",
        0xE5 => "White Watch5 Gold Edition",
        0xEC => "Black Watch6 Golf Edition",
        0xEF => "Black Watch6 TB Edition",
        _    => return None,
    })
}
