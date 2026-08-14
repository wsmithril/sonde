//! vivo manufacturer data (Company ID 0x0837) and legacy CID 0x8486.
//!
//! vivo publishes no advertising spec, but the discovery parser shipped inside
//! vivo's own earbud application has been ported to independent open-source
//! projects (`silverpoetry/HyperEars` Kotlin, `Zhaoyi-ya/TWS-Pods-PC` Python).
//! Both agree on the "TWS" fast-pair layout:
//!
//! ```text
//! byte 0    ble type       0x08 = TWS earbud
//! byte 1    protocol ver   0x01 = V1, 0x02 = V2
//! bytes 2..7 MAC address (big-endian on the wire)
//! ...
//! byte 13   model marker   if V2 && marker == 0xFF -> extended model at 16..17 (LE)
//!                          else marker byte IS the 8-bit model ID
//! ```
//!
//! (Offsets above are relative to the body after CID.) Model IDs decode to
//! internal family names (TWS1_BASE, TWS_NEO_BASE, DPD2135A, DPD2430_JOVI_*,
//! etc.); the mapping is fixed in vivo's official app and reproduced below.
//!
//! Non-TWS variants on the same CID (`ble_type != 0x08`) have no public RE, so
//! the frame is labelled and dumped as hex.
//!
//! Sources:
//! * github.com/silverpoetry/HyperEars/blob/main/protocol/src/main/java/dev/hyperears/protocol/vivo/VivoFastPairAdvertisement.kt
//! * github.com/Zhaoyi-ya/TWS-Pods-PC/blob/main/vivo/vivo_fastpair.py

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

const TWS_BLE_TYPE: u8 = 0x08;
const V1: u8 = 0x01;
const V2: u8 = 0x02;
const EXTENDED_MODEL_MARKER: u8 = 0xFF;

/// vivo — manufacturer data (Company IDs 0x0837 "new" and 0x8486 "legacy").
pub(super) struct Vivo;
impl super::VendorDecoder for Vivo {
    fn company_ids(&self) -> &'static [u16] { &[0x0837, 0x8486] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() { return; }
        // TWS fast-pair layout: body[0]=ble_type, body[1]=version, body[2..8]=MAC.
        if body.len() >= 4 && body[0] == TWS_BLE_TYPE && (body[1] == V1 || body[1] == V2) {
            Self::decode_tws(ctx, body);
            return;
        }
        // Non-TWS variant on this CID — layout not publicly documented.
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    vivo (unrecognised): frame=0x{:02X} len={}",
            body[0], body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}

impl Vivo {
    fn decode_tws(ctx: &super::DecodeCtx, body: &[u8]) {
        let ver = body[1];
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    vivo TWS: v{}", if ver == V1 { 1 } else { 2 });

        // MAC address at body[2..8] (6 bytes, big-endian on the wire).
        if body.len() >= 8 {
            let _ = write!(s, " mac=");
            super::write_mac_be(&mut s, &body[2..8]);
        }

        // Model ID at body[13], or extended 16-bit LE at body[16..18] when V2
        // and body[13] == 0xFF.
        if body.len() >= 14 {
            let marker = body[13];
            let (model_id, extended) =
                if ver == V2 && marker == EXTENDED_MODEL_MARKER && body.len() >= 18 {
                    (u16::from_le_bytes([body[16], body[17]]), true)
                } else {
                    (marker as u16, false)
                };
            let _ = write!(s, " model=0x{:04X}", model_id);
            if let Some(name) = model_name(model_id) {
                let _ = write!(s, " ({})", name);
            }
            if extended { let _ = write!(s, " [ext]"); }
        }
        emit(s);

        // Hexdump the whole body for offset reference.
        hexdump(body, ctx.base, 6);
    }
}

/// Model-ID → internal family name, from vivo's official app catalog
/// (VivoEarbudModelCatalog in the HyperEars port). Retail product names are
/// not published by vivo; these are the SDK-level identifiers.
fn model_name(id: u16) -> Option<&'static str> {
    Some(match id {
        1   => "TWS1_BASE",
        2   => "TWS1_BLACK/TWS1_TOP",
        16  => "TWS_NEO_BASE",
        17  => "TWS_NEO_BLUE",
        19  => "TWS_NEO_TOP",
        28  => "TWS2_BASE",
        29  => "TWS2_BLUE",
        31  => "TWS2_TOP",
        32  => "TWS2E_BASE",
        33  => "TWS2E_BLUE",
        35  => "TWS2E_TOP",
        48  => "DPD2135A",
        49  => "DPD2135A_BLUE",
        60  => "TWS3_BASE",
        72  => "DPD2220_BASE",
        156 => "DPD2430_BASE",
        176 => "DPD2430F_VIVO_WHITE",
        177 => "DPD2430F_VIVO_BLUE",
        180 => "DPD2430F_IQOO_BLACK",
        184 => "DPD2430F_JOVI_WHITE",
        185 => "DPD2430F_JOVI_BLUE",
        192 => "DPD2523_BASE",
        203 => "DPD2523_TOP",
        _   => return None,
    })
}
