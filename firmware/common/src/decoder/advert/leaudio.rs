//! LE Audio advertising service data (BAP / CAP profiles).
//!
//! `0x184E` Audio Stream Control Service (ASCS) — the BAP unicast announcement:
//! announcement type + Sink/Source Available Audio Contexts (the Assigned
//! Numbers "Context Type" bitfield) + optional metadata. `0x1853` Common Audio
//! Service (CAS) carries the CAP announcement (the same announcement-type byte).
//! `0x1855` Telephony and Media Audio Service (TMAS) advertises a 16-bit role
//! bitfield. `0x1852` Broadcast Audio Announcement carries the 3-byte
//! Broadcast_ID a Scan Delegator uses to sync; `0x1856` Public Broadcast
//! Announcement (PBP) adds an Auracast features byte + metadata. `0x184F`
//! Broadcast Audio Scan (BASS) and the remaining LE-Audio GATT services
//! (`0x1844` VCS, `0x1850` PACS, `0x184D` MICS) carry no fixed plaintext
//! advertising structure (Broadcast Receive State is GATT-only), so we name the
//! service and dump the rest.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// LE Audio — ASCS (0x184E), CAS (0x1853), TMAS (0x1855), BASS (0x184F), and the
/// VCS/PACS/MICS service hints (0x1844/0x1850/0x184D); dispatched by UUID.
pub(super) struct LeAudio;
impl super::VendorDecoder for LeAudio {
    fn service_uuids(&self) -> &'static [u16] {
        &[
            0x184E, 0x184F, 0x1852, 0x1853, 0x1855, 0x1856, 0x1844, 0x1850, 0x184D,
        ]
    }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        match ctx.key {
            0x184E => Self::decode_184e(body, ctx.base),
            0x184F => Self::decode_184f(body, ctx.base),
            0x1852 => Self::decode_bcast_announce(body),
            0x1856 => Self::decode_pbp(body, ctx.base),
            0x1853 => Self::decode_cas(body),
            0x1855 => Self::decode_tmas(body),
            0x1844 => Self::decode_named(body, ctx.base, "VCS (Volume Control)"),
            0x1850 => Self::decode_named(body, ctx.base, "PACS (Published Audio Caps)"),
            0x184D => Self::decode_named(body, ctx.base, "MICS (Microphone Control)"),
            _ => {}
        }
    }
}

impl LeAudio {
    fn decode_184e(f: &[u8], base: usize) {
        if f.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        let atype = match f[0] { 0 => "General", 1 => "Targeted", _ => "?" };
        let _ = write!(s, "    LE Audio ASCS: announce={}", atype);
        if f.len() >= 5 {
            let sink = u16::from_le_bytes([f[1], f[2]]);
            let src = u16::from_le_bytes([f[3], f[4]]);
            let _ = write!(s, " sink=[");
            Self::write_contexts(&mut s, sink);
            let _ = write!(s, "] src=[");
            Self::write_contexts(&mut s, src);
            let _ = write!(s, "]");
        }
        // byte5 = metadata length; metadata (LTV structures) follows if present.
        if f.len() >= 6 && f[5] as usize > 0 {
            let mlen = f[5] as usize;
            let _ = write!(s, " meta len={}", mlen);
            emit(s);
            let start = 6.min(f.len());
            let end = (6 + mlen).min(f.len());
            hexdump(&f[start..end], base + start, 6);
            return;
        }
        emit(s);
    }

    fn decode_184f(f: &[u8], base: usize) {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    LE Audio BASS (Broadcast Scan / Scan Delegator) len={}", f.len());
        emit(s);
        hexdump(f, base, 6);
    }

    /// Broadcast Audio Announcement (0x1852): the source-side counterpart to
    /// BASS — a 3-byte little-endian Broadcast_ID that a Scan Delegator matches
    /// to sync onto the broadcast isochronous stream (paired with a BIGInfo in
    /// the periodic ACAD).
    fn decode_bcast_announce(f: &[u8]) {
        let mut s: LogStr = LogStr::new();
        if f.len() >= 3 {
            let bid = u32::from_le_bytes([f[0], f[1], f[2], 0]);
            let _ = write!(s, "    LE Audio Broadcast Announce: broadcast_id=0x{:06X}", bid);
        } else {
            let _ = write!(s, "    LE Audio Broadcast Announce: truncated ({}B)", f.len());
        }
        emit(s);
    }

    /// Public Broadcast Announcement (0x1856, PBP): a features byte
    /// (bit0 Encryption, bit1 Standard-Quality, bit2 High-Quality) followed by a
    /// metadata length + LTV metadata (often the broadcast name / program info).
    fn decode_pbp(f: &[u8], base: usize) {
        if f.is_empty() {
            return;
        }
        let mut s: LogStr = LogStr::new();
        let feat = f[0];
        let _ = write!(s, "    LE Audio PBP: enc={}", if feat & 0x01 != 0 { "yes" } else { "no" });
        let mut q: LogStr = LogStr::new();
        if feat & 0x02 != 0 {
            let _ = write!(q, "SQ");
        }
        if feat & 0x04 != 0 {
            if !q.is_empty() {
                let _ = write!(q, ",");
            }
            let _ = write!(q, "HQ");
        }
        let _ = write!(s, " quality=[{}]", q.as_str());
        if f.len() >= 2 && f[1] as usize > 0 {
            let mlen = f[1] as usize;
            let _ = write!(s, " meta len={}", mlen);
            emit(s);
            let start = 2.min(f.len());
            let end = (2 + mlen).min(f.len());
            hexdump(&f[start..end], base + start, 6);
            return;
        }
        emit(s);
    }

    /// CAS (0x1853): the CAP announcement — a single announcement-type byte
    /// (General/Targeted), same encoding as the ASCS announcement.
    fn decode_cas(f: &[u8]) {
        let mut s: LogStr = LogStr::new();
        let atype = match f.first() { Some(0) => "General", Some(1) => "Targeted", _ => "?" };
        let _ = write!(s, "    LE Audio CAS: announce={}", atype);
        emit(s);
    }

    /// TMAS (0x1855): a 16-bit "TMAP Role" bitfield (Telephony & Media Audio
    /// Profile §3.1) — which call/media roles the device supports.
    fn decode_tmas(f: &[u8]) {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    LE Audio TMAS: role=[");
        if f.len() >= 2 {
            let role = u16::from_le_bytes([f[0], f[1]]);
            const NAMES: [&str; 6] = ["CG", "CT", "UMS", "UMR", "BMS", "BMR"];
            let mut first = true;
            for (i, n) in NAMES.iter().enumerate() {
                if role & (1 << i) != 0 {
                    if !first { let _ = write!(s, ","); }
                    let _ = write!(s, "{}", n);
                    first = false;
                }
            }
            if first { let _ = write!(s, "none"); }
            let _ = write!(s, "] (0x{:04X})", role);
        } else {
            let _ = write!(s, "?]");
        }
        emit(s);
    }

    /// The remaining LE-Audio GATT services appear in advertising only as a
    /// capability hint; name the service and dump any bytes present.
    fn decode_named(f: &[u8], base: usize, name: &str) {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    LE Audio {} len={}", name, f.len());
        emit(s);
        hexdump(f, base, 6);
    }

    /// Append the set "Context Type" bits (Assigned Numbers §6.12.3) as short names.
    fn write_contexts(s: &mut LogStr, bits: u16) {
        const NAMES: [&str; 12] = [
            "Unspec", "Conv", "Media", "Game", "Instr", "VA",
            "Live", "SFX", "Notif", "Ring", "Alert", "Emrg",
        ];
        if bits == 0 {
            let _ = write!(s, "none");
            return;
        }
        let mut first = true;
        for (i, n) in NAMES.iter().enumerate() {
            if bits & (1 << i) != 0 {
                if !first { let _ = write!(s, ","); }
                let _ = write!(s, "{}", n);
                first = false;
            }
        }
        let extra = bits & !0x0FFF;
        if extra != 0 { let _ = write!(s, ",+0x{:03X}", extra); }
    }
}
