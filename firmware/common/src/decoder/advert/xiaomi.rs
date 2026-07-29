//! Xiaomi advertising decoders. Two distinct formats:
//!
//! * `decode_mibeacon` — the public MiBeacon *service data* (UUID 0xFE95):
//!   Frame Control (2B LE) + Product ID (2B LE) + counter (1B), optional
//!   MAC/capability, then TLV sensor objects. Encrypted payloads stay hex.
//! * `decode_mfg` — Xiaomi *manufacturer-specific data* (Company ID 0x038F),
//!   which is proprietary/undocumented (see below).

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Xiaomi — MiBeacon service data (UUID 0xFE95) and manufacturer data
/// (Company ID 0x038F); dispatched by frame kind.
pub(super) struct Xiaomi;
impl super::VendorDecoder for Xiaomi {
    fn company_ids(&self) -> &'static [u16] { &[0x038F] }
    fn service_uuids(&self) -> &'static [u16] { &[0xFE95] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        match ctx.kind {
            super::FrameKind::Mfg => Self::decode_mfg(body, ctx.base),
            super::FrameKind::Service => Self::decode_mibeacon(body, ctx.base),
        }
    }
}

impl Xiaomi {
    fn decode_mibeacon(f: &[u8], base: usize) {
        if f.len() < 5 { return; }
        let fc        = u16::from_le_bytes([f[0], f[1]]);
        let product   = u16::from_le_bytes([f[2], f[3]]);
        let counter   = f[4];
        // Frame Control bitfield (LE): 3=encrypted, 4=MAC, 5=capability, 6=object,
        // 7=mesh, 8=registered, 9=solicited, 10-11=auth mode, 12-15=version.
        let encrypted = (fc >> 3) & 1 != 0;
        let mac_inc   = (fc >> 4) & 1 != 0;
        let cap_inc   = (fc >> 5) & 1 != 0;
        let obj_inc   = (fc >> 6) & 1 != 0;
        let mesh      = (fc >> 7) & 1 != 0;
        let registered = (fc >> 8) & 1 != 0;
        let solicited = (fc >> 9) & 1 != 0;
        let auth_mode = (fc >> 10) & 0x03;
        let version   = (fc >> 12) & 0x0F;

        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    MiBeacon: product=0x{:04X} cnt={} v{} enc={} auth={}",
            product, counter, version, encrypted, auth_mode);
        if let Some(model) = Self::product_name(product) {
            let _ = write!(s, " model={}", model);
        }
        if mesh       { let _ = write!(s, " mesh"); }
        if registered { let _ = write!(s, " registered"); }
        if solicited  { let _ = write!(s, " solicited"); }
        // The optional MAC is the device's real, static hardware address, carried
        // in the clear inside the service data. It does not rotate with the
        // advertising RPA, so it defeats address privacy on its own — the same
        // class of leak the report's security section tracks for other vendors.
        // Print it rather than skipping past it to reach the sensor objects.
        if mac_inc && f.len() >= 11 {
            let a = &f[5..11];
            let _ = write!(s, " mac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                a[5], a[4], a[3], a[2], a[1], a[0]);
        }
        let _ = write!(s, "\r\n");
        emit(s);

        // Step past the MAC and capability fields to reach the object section.
        let mut idx = 5;
        if mac_inc { idx += 6; }
        if cap_inc {
            if idx >= f.len() { return; }
            let cap = f[idx];
            idx += 1;
            if cap & 0x20 != 0 { idx += 2; } // extended I/O capability
        }
        if encrypted || !obj_inc { return; }

        // TLV objects: [type u16 LE][len u8][data].
        while idx + 3 <= f.len() {
            let otype = u16::from_le_bytes([f[idx], f[idx + 1]]);
            let olen  = f[idx + 2] as usize;
            if idx + 3 + olen > f.len() { break; }
            Self::decode_object(otype, &f[idx + 3..idx + 3 + olen], base + idx + 3);
            idx += 3 + olen;
        }
    }

    /// Xiaomi product-ID → model name, from the ble_monitor project
    /// (github.com/custom-components/ble_monitor, ble_parser/xiaomi.py). Covers the
    /// sensor devices ble_monitor tracks; non-sensor products stay unnamed. Sorted
    /// by ID for binary search.
    const PRODUCTS: &'static [(u16, &'static str)] = &[
        (0x0083, "YM-K1501"), (0x0098, "HHCCJCY01"), (0x00DB, "MMC-T201-1"),
        (0x0113, "YM-K1501EU"), (0x0153, "YLYK01YL"), (0x015D, "HHCCPOT002"),
        (0x01AA, "LYWSDCGQ"), (0x02DF, "JQJCY01YM"), (0x0347, "CGG1"),
        (0x0380, "DSL-C08"), (0x0387, "MHO-C401"), (0x0391, "MMC-W505"),
        (0x03B6, "YLKG07YL/YLKG08YL"), (0x03BC, "GCLS002"), (0x03BF, "YLYB01YL-BHFRC"),
        (0x03D6, "CGH1"), (0x03DD, "MUE4094RT"), (0x040A, "WX08ZM"),
        (0x045B, "LYWSD02"), (0x045C, "V-SK152"), (0x0489, "M1S-T500"),
        (0x04E1, "XMMF01JQD"), (0x04E6, "YLYK01YL-VENFAN"), (0x04E9, "MJZNMSQ01YD"),
        (0x055B, "LYWSD03MMC"), (0x0576, "CGD1"), (0x066F, "CGDK2"),
        (0x068E, "YLYK01YL-FANCL"), (0x069E, "ZNMS16LM"), (0x069F, "ZNMS17LM"),
        (0x06D3, "MHO-C303"), (0x0784, "XMZNMS04LM"), (0x07BF, "YLAI003"),
        (0x07F6, "MJYD02YL"), (0x0806, "T700"), (0x0863, "SJWS01LM"),
        (0x098B, "MCCGQ02HL"), (0x098C, "XMZNMST02YD"), (0x0997, "JTYJGD03MI"),
        (0x0A83, "CGPR1"), (0x0A8D, "RTCGQ02LM"), (0x0B48, "CGG1-ENCRYPTED"),
        (0x0C3C, "CGC1"), (0x0DE7, "SU001-T"), (0x0DFD, "K9B-3BTN"),
        (0x0E39, "XMZNMS08LM"), (0x11C2, "SV40"), (0x1203, "XMWSDJ04MMC"),
        (0x1568, "K9B-1BTN"), (0x1569, "K9B-2BTN"), (0x16E4, "LYWSD02MMC"),
        (0x1790, "T700i"), (0x1889, "MS1BB(MI)"), (0x18E3, "ZX1"),
        (0x1949, "XMWXKG01YL"), (0x1C10, "K9BB-1BTN"), (0x20DB, "MJZNZ018H"),
        (0x2387, "XMWXKG01LM"), (0x2542, "LYWSD02MMC"), (0x2832, "MJWSD05MMC"),
        (0x2AEB, "HS1BB(MI)"), (0x3531, "XMPIRO2SXS"), (0x38BB, "PTX"),
        (0x3A61, "KS1"), (0x3BD5, "MJTZC01YM"), (0x3E17, "KS1BP"),
        (0x3F0F, "RS1BB"), (0x3F4C, "PS1BB"), (0x4683, "XMOSB01XS"),
        (0x4F59, "CGDK3"), (0x50FB, "ES3"), (0x55B5, "MJWSD06MMC"),
        (0x5808, "CGG3"), (0x5DB1, "MBS17"), (0x64C5, "PTX-F1-Display"),
    ];

    fn product_name(id: u16) -> Option<&'static str> {
        Self::PRODUCTS
            .binary_search_by_key(&id, |&(k, _)| k)
            .ok()
            .map(|i| Self::PRODUCTS[i].1)
    }

    fn decode_object(t: u16, d: &[u8], base: usize) {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    MiBeacon obj 0x{:04X}: ", t);
        let mut tail: Option<&[u8]> = None;
        match t {
            0x1004 if d.len() >= 2 => {
                let v = i16::from_le_bytes([d[0], d[1]]);
                let _ = write!(s, "temp {}.{} C", v / 10, (v % 10).abs());
            }
            0x1006 if d.len() >= 2 => {
                let v = u16::from_le_bytes([d[0], d[1]]);
                let _ = write!(s, "humidity {}.{}%", v / 10, v % 10);
            }
            0x100A if !d.is_empty() => { let _ = write!(s, "battery {}%", d[0]); }
            0x100D if d.len() >= 4 => {
                let tv = i16::from_le_bytes([d[0], d[1]]);
                let hv = u16::from_le_bytes([d[2], d[3]]);
                let _ = write!(s, "temp {}.{} C humidity {}.{}%",
                    tv / 10, (tv % 10).abs(), hv / 10, hv % 10);
            }
            0x1007 if d.len() >= 3 => {
                let lux = u32::from_le_bytes([d[0], d[1], d[2], 0]);
                let _ = write!(s, "illuminance {} lux", lux);
            }
            0x1008 if !d.is_empty() => { let _ = write!(s, "moisture {}%", d[0]); }
            0x1009 if d.len() >= 2 => {
                let _ = write!(s, "conductivity {} uS/cm", u16::from_le_bytes([d[0], d[1]]));
            }
            0x1010 if d.len() >= 2 => {
                let v = u16::from_le_bytes([d[0], d[1]]);
                let _ = write!(s, "formaldehyde {}.{:02} mg/m3", v / 100, v % 100);
            }
            // Object layouts below are from the Bluetooth-Devices/xiaomi-ble parser
            // (github.com/Bluetooth-Devices/xiaomi-ble, xiaomi_ble/parser.py).
            0x0003 => { let _ = write!(s, "motion detected"); }
            0x0006 if d.len() >= 5 => {
                let key = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
                let _ = write!(s, "fingerprint key=0x{:08X} match=0x{:02X}", key, d[4]);
            }
            0x0007 if !d.is_empty() => {
                let _ = write!(s, "door {}", if d[0] == 0 { "open" } else { "closed/other" });
            }
            0x000F if d.len() >= 3 => {
                let illum = u32::from_le_bytes([d[0], d[1], d[2], 0]);
                let _ = write!(s, "motion, illuminance {} lux", illum);
            }
            0x1005 if d.len() >= 2 => {
                let _ = write!(s, "power {} temp {} C",
                    if d[0] != 0 { "on" } else { "off" }, d[1] as i8);
            }
            0x100E if !d.is_empty() => { let _ = write!(s, "lock attr=0x{:02X}", d[0]); }
            0x1012 if !d.is_empty() => {
                let _ = write!(s, "power {}", if d[0] != 0 { "on" } else { "off" });
            }
            0x1013 if !d.is_empty() => { let _ = write!(s, "consumable {}%", d[0]); }
            0x1014 if !d.is_empty() => {
                let _ = write!(s, "moisture/leak {}", if d[0] > 0 { "yes" } else { "no" });
            }
            0x1015 if !d.is_empty() => {
                let _ = write!(s, "smoke {}", if d[0] > 0 { "yes" } else { "no" });
            }
            0x1017 if d.len() >= 4 => {
                let secs = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
                let _ = write!(s, "no motion for {} s", secs);
            }
            0x1018 if !d.is_empty() => {
                let _ = write!(s, "light {}", if d[0] > 0 { "yes" } else { "no" });
            }
            0x1019 if !d.is_empty() => { let _ = write!(s, "opening state=0x{:02X}", d[0]); }
            _ => tail = Some(d),
        }
        if let Some(t) = tail
            && !t.is_empty()
        {
            let _ = write!(s, "len={}", t.len());
        }
        emit(s);
        if let Some(t) = tail {
            hexdump(t, base, 6);
        }
    }

    // ── Manufacturer-specific data (Company ID 0x038F) ───────────────────────
    //
    // This format is proprietary and undocumented — no public tool (ble_monitor,
    // ESPHome, Theengs, reelyActive advlib) decodes it; they all target the 0xFE95
    // MiBeacon service data instead. The field layout below is reverse-engineered
    // from captured traffic and is best-effort, not a spec:
    //
    //   * The first two bytes are a frame opcode from a small fixed set
    //     (0x0A10, 0x1601, 0x2C11 observed).
    //   * Payloads are static per device (presence/keepalive, not sensor telemetry).
    //   * Each frame embeds one or two 6-byte MAC-like identifiers; 0x1601 carries
    //     the same MAC twice, 0x0A10 carries one at a fixed offset. This matches
    //     Xiaomi BLE Mesh presence advertising (a stable id under a rotating MAC).
    //
    // Recognised structure is surfaced; unknown bytes stay as hex.
    fn decode_mfg(data: &[u8], base: usize) {
        if data.len() < 2 { return; }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Xiaomi mfg (proprietary, mesh?) type=0x{:02X}{:02X}",
            data[0], data[1]);
        // Variable-length trailing bytes are hexdumped after the header line; the
        // short fixed fields (state, header, MAC) stay inline.
        let mut tail: Option<(&[u8], usize)> = None;
        match (data[0], data[1]) {
            (0x0A, 0x10) if data.len() >= 11 => {
                // 0A10 [3B state] [6B MAC] [1B trailer] ([extra]).
                let _ = write!(s, " state=");
                write_hex(&mut s, &data[2..5]);
                let _ = write!(s, " id=");
                Self::write_mac_rev(&mut s, &data[5..11]);
                if data.len() > 11 {
                    let _ = write!(s, " tail");
                    tail = Some((&data[11..], base + 11));
                }
            }
            (0x16, 0x01) if data.len() >= 24 => {
                // 1601 [9B header] [6B MAC] [1B sep] [6B MAC].
                let mac1 = &data[11..17];
                let mac2 = &data[18..24];
                let _ = write!(s, " hdr=");
                write_hex(&mut s, &data[2..11]);
                let _ = write!(s, " id=");
                Self::write_mac_rev(&mut s, mac1);
                if mac1 == mac2 {
                    let _ = write!(s, " (x2 sep=0x{:02X})", data[17]);
                } else {
                    let _ = write!(s, " id2=");
                    Self::write_mac_rev(&mut s, mac2);
                }
            }
            _ => {
                // Unknown opcode — keep the body as hex.
                tail = Some((&data[2..], base + 2));
            }
        }
        if let Some((t, _)) = tail
            && !t.is_empty()
        {
            let _ = write!(s, " len={}", t.len());
        }
        emit(s);
        if let Some((t, b)) = tail {
            hexdump(t, b, 6);
        }
    }

    /// Print a 6-byte MAC MSB-first (payload carries it LSB-first, like the air
    /// address), matching the packet header's address format.
    fn write_mac_rev(s: &mut LogStr, m: &[u8]) {
        for (i, b) in m.iter().rev().enumerate() {
            if i > 0 { let _ = write!(s, ":"); }
            let _ = write!(s, "{:02X}", b);
        }
    }
}
