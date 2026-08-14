//! Sony manufacturer data (Company ID 0x012D).
//!
//! There is no official public spec, but Sony camera and audio broadcasts have
//! been reverse-engineered by the community. Layout after CID:
//!
//! ```text
//! body[0..2]  device type ID (LE)   0x0003 = camera (documented),
//!                                   0x0004 / 0x0013 = audio (observed)
//! body[2]     BLE protocol version  0x64 = Imaging Edge app, 0x65 = Creator's App
//! body[3..]   device-type-specific  (see below)
//! ```
//!
//! For **cameras** (device type 0x0003) the tail is:
//! ```text
//! body[4..6]  ASCII model code      "E1", "A1", "U1"
//! body[6..]   3-byte TLV blocks     <TagID><LE u16 value>
//!             0x21  power / Wi-Fi handover flags
//!             0x22  pairing / remote-control flags
//!             0x23  push notification / image transfer flags
//! ```
//! (github.com/ekutner/camera-gps-link/blob/main/sony-camera-bt-info.md
//! consolidating gethypoxic.com/blogs/technical/sony-camera-ble-control-protocol-di-remote-control,
//! gregleeds.com/reverse-engineering-sony-camera-bluetooth/, and
//! github.com/whc2001/ILCE7M3ExternalGps.)
//!
//! For **audio** devices (0x0004 / 0x0013 observed) the current firmware
//! surfaces the header and dumps the tail; per adwatch RE
//! (github.com/bensmith83/adwatch/blob/main/docs/protocols/sony-audio.md)
//! bytes 4..8 encode a model ID and bytes 8..12 a device address, but tag /
//! flag semantics are not defined for audio and are left as hex.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Sony Corporation — manufacturer data (Company ID 0x012D).
pub(super) struct Sony;
impl super::VendorDecoder for Sony {
    fn company_ids(&self) -> &'static [u16] { &[0x012D] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 3 {
            hexdump(body, ctx.base, 6);
            return;
        }
        let cat = u16::from_le_bytes([body[0], body[1]]);
        let ver = body[2];
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Sony: device-type=0x{:04X} ({}) ver=0x{:02X} ({}) len={}",
            cat, category(cat), ver, version_name(ver), body.len() - 3);
        emit(s);

        match cat {
            0x0003 => Sony::decode_camera(ctx, body),
            0x0004 | 0x0013 => Sony::decode_audio(ctx, body),
            _ => { hexdump(&body[3..], ctx.base + 3, 6); }
        }
    }
}

impl Sony {
    /// Camera frame: 2-byte ASCII model code at bytes 3..5 (some captures start
    /// the model at 4; try both), then TLV blocks `<tag><LE u16>`.
    fn decode_camera(ctx: &super::DecodeCtx, body: &[u8]) {
        // ASCII model code: bytes 4..6 per the ekutner writeup, which uses the
        // BLE protocol version at byte 2 (offset from CID) then model at 4..5.
        // Guard on printable ASCII so we don't fabricate a code from binary.
        if body.len() >= 6
            && is_ascii_printable(body[4])
            && is_ascii_printable(body[5])
        {
            let mut s: LogStr = LogStr::new();
            let _ = write!(s, "    Sony camera: model=\"{}{}\"",
                body[4] as char, body[5] as char);
            emit(s);
        }
        // Scan the tail for TLV tag blocks. Start past the fixed header so a
        // header byte cannot false-match a tag.
        scan_camera_tags(body, ctx.base);
        hexdump(&body[3..], ctx.base + 3, 6);
    }

    /// Audio frame: layout documented but tag / flag semantics are not, so we
    /// surface what the adwatch RE names and leave the rest as hex.
    fn decode_audio(ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() >= 8 {
            let model = u16::from_le_bytes([body[4], body[5]]);
            let mut s: LogStr = LogStr::new();
            let _ = write!(s, "    Sony audio: model-id=0x{:04X}", model);
            if body.len() >= 12 {
                let _ = write!(s, " addr=");
                write_hex(&mut s, &body[8..12]);
            }
            emit(s);
        }
        hexdump(&body[3..], ctx.base + 3, 6);
    }
}

/// Emit one decoded flag line per known TLV tag found past the header.
fn scan_camera_tags(body: &[u8], _base: usize) {
    let mut i = 6usize; // skip device-type (2) + version (1) + model code (2..3)
    while i + 2 < body.len() {
        let tag = body[i];
        let val = u16::from_le_bytes([body[i + 1], body[i + 2]]);
        match tag {
            0x21 => {
                let mut s: LogStr = LogStr::new();
                let _ = write!(s, "      tag=0x21 val=0x{:04X}", val);
                if val & 0x0040 != 0 { let _ = write!(s, " camera-powered-on"); }
                if val & 0x0080 != 0 { let _ = write!(s, " remote-power-enabled"); }
                if val & 0x0010 != 0 { let _ = write!(s, " wifi-handover-enabled"); }
                if val & 0x0020 != 0 { let _ = write!(s, " wifi-handover-supported"); }
                emit(s);
                i += 3;
                continue;
            }
            0x22 => {
                let mut s: LogStr = LogStr::new();
                let _ = write!(s, "      tag=0x22 val=0x{:04X}", val);
                if val & 0x0080 != 0 { let _ = write!(s, " pairing-supported"); }
                if val & 0x0040 != 0 { let _ = write!(s, " pairing-enabled"); }
                if val & 0x0020 != 0 { let _ = write!(s, " location-supported"); }
                if val & 0x0010 != 0 { let _ = write!(s, " location-enabled"); }
                if val & 0x0004 != 0 { let _ = write!(s, " remote-enabled(0x65)"); }
                if val & 0x0002 != 0 { let _ = write!(s, " remote-enabled"); }
                if val & 0x0042 == 0x0042 { let _ = write!(s, " [ready-to-pair]"); }
                emit(s);
                i += 3;
                continue;
            }
            0x23 => {
                let mut s: LogStr = LogStr::new();
                let _ = write!(s, "      tag=0x23 val=0x{:04X}", val);
                if val & 0x0001 != 0 { let _ = write!(s, " push-notifications-enabled"); }
                if val & 0x0002 != 0 { let _ = write!(s, " push-notifications-supported"); }
                if val & 0x0010 != 0 { let _ = write!(s, " image-transfer-supported"); }
                if val & 0x0004 == 0x0004 && val & 0x000C == 0x0004 {
                    let _ = write!(s, " image-transfer-enabled");
                }
                if val & 0x0080 != 0 { let _ = write!(s, " remote-control-supported"); }
                if val & 0x0060 == 0x0020 { let _ = write!(s, " remote-control-enabled"); }
                emit(s);
                i += 3;
                continue;
            }
            _ => { i += 1; } // walk past unknown bytes
        }
    }
}

fn is_ascii_printable(b: u8) -> bool { (0x20..=0x7E).contains(&b) }

fn category(c: u16) -> &'static str {
    match c {
        0x0003 => "camera",
        0x0004 | 0x0013 => "audio",
        _ => "?",
    }
}

fn version_name(v: u8) -> &'static str {
    match v {
        0x64 => "Imaging Edge",
        0x65 => "Creator's App",
        _    => "?",
    }
}
