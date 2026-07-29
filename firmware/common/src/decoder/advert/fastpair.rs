//! Google Fast Pair (service UUID 0xFE2C).
//!
//! A 3-byte body is a plaintext Model ID (device in pairing/discoverable mode).
//! Anything longer is the non-discoverable Account Key Data: a sequence of
//! `[len<<4 | type]` fields — account-key bloom filter (opaque), salt (opaque),
//! and an optional **battery** field which IS plaintext (left/right/case level +
//! charging). We label each field and decode the battery values.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// A small, community-sourced subset of the 24-bit Fast Pair Model ID registry
/// (Google keeps the full 4000+ list private). Enough to name the common earbuds
/// and speakers seen in the wild; unknown IDs still print as raw hex. Values that
/// conflict between public sources are omitted rather than guessed.
const FASTPAIR_MODELS: &[(u32, &str)] = &[
    (0x000006, "Google Pixel Buds"),
    (0x92BBBD, "Google Pixel Buds A-Series"),
    (0x0000F0, "Bose QC 35 II"),
    (0xCD8256, "Bose NC 700"),
    (0xF52494, "JBL Buds Pro"),
    (0x718FA4, "JBL Live 300TWS"),
    (0x821F66, "JBL Flip 6"),
    (0xD446A7, "Sony WF-1000XM5"),
    (0x2D7A23, "Sony WF-1000XM4"),
    (0x0001F0, "Bisto CSR8670 dev board"),
    (0x000047, "Arduino 101"),
    (0x00000A, "Fast Pair anti-spoofing test"),
];

fn model_name(id: u32) -> Option<&'static str> {
    FASTPAIR_MODELS
        .iter()
        .find(|(m, _)| *m == id)
        .map(|(_, name)| *name)
}

/// Google Fast Pair — service data (UUID 0xFE2C).
pub(super) struct FastPair;
impl super::VendorDecoder for FastPair {
    fn service_uuids(&self) -> &'static [u16] { &[0xFE2C] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        let f = body;
        let base = ctx.base;
        let mut s: LogStr = LogStr::new();
        if f.len() == 3 {
            let model = u32::from_be_bytes([0, f[0], f[1], f[2]]);
            let _ = write!(s, "    FastPair: model=0x{:06X}", model);
            if let Some(name) = model_name(model) {
                let _ = write!(s, " ({})", name);
            }
            let _ = write!(s, " (pairing)");
            emit(s);
            return;
        }
        if f.is_empty() { return; }

        // Non-discoverable: walk the [len<<4 | type] account-key-data fields.
        let _ = write!(s, "    FastPair non-discoverable:");
        let mut battery: Option<(usize, usize)> = None; // (start, len) of a battery field
        let mut i = 0;
        while i < f.len() {
            let len = (f[i] >> 4) as usize;
            let typ = f[i] & 0x0F;
            let bstart = i + 1;
            let bend = (bstart + len).min(f.len());
            match typ {
                0x0 => { let _ = write!(s, " akf(show,{}B)", len); }
                0x2 => { let _ = write!(s, " akf(hidden,{}B)", len); }
                0x1 => { let _ = write!(s, " salt({}B)", len); }
                0x3 | 0x4 => {
                    let _ = write!(s, " battery({})",
                        if typ == 0x3 { "show" } else { "hidden" });
                    battery = Some((bstart, bend - bstart));
                }
                _ => { let _ = write!(s, " field(type=0x{:X},{}B)", typ, len); }
            }
            i = bend; // bend >= i+1 always, so the walk terminates
        }

        // Battery: each byte = bit7 charging, bits0-6 level (0-100, 0x7F unknown).
        if let Some((bs, blen)) = battery {
            const LABELS: [&str; 3] = ["L", "R", "case"];
            let _ = write!(s, " [");
            for k in 0..blen {
                let v = f[bs + k];
                let lbl = LABELS.get(k).copied().unwrap_or("?");
                if k > 0 { let _ = write!(s, " "); }
                let lvl = v & 0x7F;
                if lvl == 0x7F {
                    let _ = write!(s, "{}=?", lbl);
                } else {
                    let _ = write!(s, "{}={}%{}", lbl, lvl, if v & 0x80 != 0 { "+" } else { "" });
                }
            }
            let _ = write!(s, "]");
        }
        emit(s);
        hexdump(f, base, 6);
    }
}
