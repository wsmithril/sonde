//! Apple "Continuity" manufacturer data (Company ID 0x004C).
//!
//! The payload is a stream of `[type][len][payload]` sub-messages. Plaintext,
//! structured fields (AirPods battery, Instant Hotspot battery/cellular, AirPlay
//! IPv4, NearbyInfo activity, Find My battery, AWDL flags) are decoded;
//! encrypted/rotating identity fields are labelled but kept as hex.
//!
//! Field layouts and the message-type / action / activity enums follow the
//! FuriousMAC Continuity dissector: https://github.com/furiousMAC/continuity
//! (see its `dissector/FIELDS.md`).

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Apple, Inc. — manufacturer data (Company ID 0x004C): iBeacon, AirDrop,
/// Handoff, Nearby, AirPods/Find My continuity messages; plus the Apple service
/// frames 0xFCB2 (pairing/proximity) and 0xFD44 (AirPrint), which have no public
/// plaintext layout and are labelled + dumped.
pub(super) struct Apple;
impl super::VendorDecoder for Apple {
    fn company_ids(&self) -> &'static [u16] { &[0x004C] }
    fn service_uuids(&self) -> &'static [u16] { &[0xFCB2, 0xFD44] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if let super::FrameKind::Service = ctx.kind {
            Self::decode_service(ctx, body);
            return;
        }
        let data = body;
        let base = ctx.base;
        let mut i = 0;
        while i + 1 < data.len() {
            let mtype = data[i];
            // Type 0x00 is not a Continuity message — it is the zero padding that
            // follows the last real sub-message in the AD (the message types Apple
            // assigns start at 0x02). Stop here rather than emit a phantom empty
            // `Apple ? (0x00)` for each trailing zero byte.
            if mtype == 0x00 {
                break;
            }
            let mlen  = data[i + 1] as usize;
            let start = i + 2;
            let end   = start + mlen;
            if end > data.len() { break; }
            let p = &data[start..end];

            let mut s: LogStr = LogStr::new();
            let _ = write!(s, "    Apple {} (0x{:02X}): ", Self::msg_name(mtype), mtype);

            // Opaque/encrypted trailing bytes are hexdumped after the header line.
            let mut tail: Option<(&[u8], usize)> = None;
            match mtype {
                0x02 if p.len() >= 21 => {
                    // iBeacon: 16B proximity UUID, major (BE), minor (BE), measured power (i8).
                    for (k, b) in p[0..16].iter().enumerate() {
                        let _ = write!(s, "{:02X}", b);
                        if matches!(k, 3 | 5 | 7 | 9) { let _ = write!(s, "-"); }
                    }
                    let major = u16::from_be_bytes([p[16], p[17]]);
                    let minor = u16::from_be_bytes([p[18], p[19]]);
                    let power = p[20] as i8;
                    let _ = write!(s, " major={} minor={} pwr={}dBm", major, minor, power);
                }
                0x07 if p.len() >= 6 => {
                    // ProximityPair (AirPods family): model + battery/charging status.
                    // p[0]=prefix, p[1..3]=model(BE), p[3]=status, p[4]=pod batteries,
                    // p[5]=charging flags(hi) + case battery(lo). Remaining bytes are
                    // an encrypted payload that stays as the outer hex dump.
                    let model  = u16::from_be_bytes([p[1], p[2]]);
                    let status = p[3];
                    // status bit1 clear ⇒ pod battery nibbles are (left, right) swapped.
                    let flip = (status & 0x02) == 0;
                    let (hi, lo) = (p[4] >> 4, p[4] & 0x0F);
                    let (left, right) = if flip { (lo, hi) } else { (hi, lo) };
                    let charge = p[5] >> 4;
                    let case_b = p[5] & 0x0F;
                    let _ = write!(s, "{} (0x{:04X})", Self::model_name(model), model);
                    Self::write_batt(&mut s, "L", left);
                    Self::write_batt(&mut s, "R", right);
                    Self::write_batt(&mut s, "case", case_b);
                    // charge nibble: bit0=right, bit1=left, bit2=case.
                    let _ = write!(s, " chg[");
                    if charge & 0x01 != 0 { let _ = write!(s, "R"); }
                    if charge & 0x02 != 0 { let _ = write!(s, "L"); }
                    if charge & 0x04 != 0 { let _ = write!(s, "C"); }
                    let _ = write!(s, "]");
                }
                0x09 if p.len() >= 6 => {
                    // AirPlay target: flags, a seed that increments as the RPA
                    // rotates, and an IPv4 address. The IP is a genuine plaintext
                    // leak when populated (it reads 0.0.0.0 while idle). Verified
                    // against live captures; still plaintext on current iOS.
                    let _ = write!(s, "flags=0x{:02X} seed={} ip={}.{}.{}.{}",
                        p[0], p[1], p[2], p[3], p[4], p[5]);
                }
                0x0C if p.len() >= 3 => {
                    // Handoff: a clipboard copy/cut flag and a sequence-number IV
                    // (increments per message); the auth tag and handoff data after
                    // it are AES-GCM encrypted, so they stay as the hex tail.
                    // Verified against live captures.
                    let seq = u16::from_le_bytes([p[1], p[2]]);
                    let _ = write!(s, "clipboard={} seq={}",
                        if p[0] != 0 { "yes" } else { "no" }, seq);
                    if p.len() > 3 { tail = Some((&p[3..], base + start + 3)); }
                }
                0x0F if !p.is_empty() => {
                    // NearbyAction: flags, action type, 3-byte auth tag, then params.
                    let _ = write!(s, "flags=0x{:02X}", p[0]);
                    if p.len() > 1 {
                        let _ = write!(s, " action={}(0x{:02X})", Self::action_name(p[1]), p[1]);
                    }
                    // Auth tag + type-specific parameters are opaque — keep as hex.
                    if p.len() > 2 { tail = Some((&p[2..], base + start + 2)); }
                }
                0x10 if !p.is_empty() => {
                    // NearbyInfo: high nibble = status flags (bitmask), low nibble =
                    // action/activity code. byte1 = data flags; rest = rotating auth tag.
                    let sf = p[0] >> 4;
                    let ac = p[0] & 0x0F;
                    let _ = write!(s, "action={}(0x{:X}) flags[", Self::activity_name(ac), ac);
                    if sf & 0x01 != 0 { let _ = write!(s, "primary "); }
                    if sf & 0x04 != 0 { let _ = write!(s, "airdrop "); }
                    let _ = write!(s, "]");
                    if p.len() > 1 { let _ = write!(s, " df=0x{:02X}", p[1]); }
                    if p.len() > 2 { let _ = write!(s, " auth"); tail = Some((&p[2..], base + start + 2)); }
                }
                0x12 if !p.is_empty() => {
                    // FindMy: status byte carries a coarse battery level in bits 6-7
                    // and a "maintained" flag (bit2). Rest = rotating public-key bits.
                    let batt = match (p[0] >> 6) & 0x03 {
                        0 => "full", 1 => "medium", 2 => "low", _ => "critical",
                    };
                    let _ = write!(s, "battery={} maintained={}", batt, (p[0] & 0x04) != 0);
                    if p.len() > 1 { tail = Some((&p[1..], base + start + 1)); }
                }
                0x16 if !p.is_empty() => {
                    // AWDL (Apple Wireless Direct Link) peer-discovery beacon: p[0]
                    // is an Apple flags byte, the rest a rotating AWDL link value
                    // that changes in lockstep with the advertising RPA (likely a
                    // hash over fixed data and the address), so it stays as hex. A
                    // device that beacons only this, non-connectable and constantly,
                    // is an AWDL source doing AirPlay/AirDrop/Sidecar/Continuity-
                    // Camera discovery — Apple TV, Mac or iPhone. Carries no battery.
                    let _ = write!(s, "flags=0x{:02X}", p[0]);
                    if p.len() > 1 { tail = Some((&p[1..], base + start + 1)); }
                }
                _ => {
                    // Other continuity types are typically encrypted/rotating — hex only.
                    tail = Some((p, base + start));
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
            i = end;
        }
    }
}

impl Apple {
    /// Apple service-data frames (AD 0x16). Neither 0xFCB2 nor 0xFD44 has a public
    /// plaintext layout, so we name the source and dump the rotating body.
    fn decode_service(ctx: &super::DecodeCtx, body: &[u8]) {
        let name = match ctx.key {
            0xFCB2 => "Apple 0xFCB2 (pairing/proximity)",
            _ => "Apple 0xFD44 (AirPrint)",
        };
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    {} len={}", name, body.len());
        emit(s);
        hexdump(body, ctx.base, 6);
    }

    /// Continuity sub-message type → name.
    fn msg_name(t: u8) -> &'static str {
        match t {
            0x02 => "iBeacon",
            0x03 => "AirPrint",
            0x05 => "AirDrop",
            0x06 => "HomeKit",
            0x07 => "ProximityPair", // AirPods & friends
            0x08 => "HeySiri",
            0x09 => "AirPlayTarget",
            0x0A => "AirPlaySource",
            0x0B => "MagicSwitch", // Apple Watch wrist detect
            0x0C => "Handoff",
            0x0D => "TetherTarget",
            0x0E => "TetherSource",
            0x0F => "NearbyAction",
            0x10 => "NearbyInfo",
            0x12 => "FindMy",
            0x16 => "AWDL",
            _    => "?",
        }
    }

    /// Apple ProximityPair device model → product name. The 2-byte model is what
    /// the AirPods family advertises to trigger the pairing popup.
    fn model_name(m: u16) -> &'static str {
        match m {
            0x0220 => "AirPods (1st gen)",
            0x0F20 => "AirPods (2nd gen)",
            0x1320 => "AirPods (3rd gen)",
            0x1920 => "AirPods (4th gen)",
            0x0E20 => "AirPods Pro",
            0x1420 => "AirPods Pro (2nd gen)",
            0x0A20 => "AirPods Max",
            0x1120 => "Powerbeats Pro",
            0x1020 => "Beats Solo Pro",
            0x1720 => "Beats Studio Buds",
            0x1220 => "Beats Fit Pro",
            _      => "?",
        }
    }

    /// Append " L=xx%" style battery, or "?" when the nibble is 0x0F (disconnected).
    fn write_batt(s: &mut LogStr, label: &str, nibble: u8) {
        if nibble == 0x0F {
            let _ = write!(s, " {}=?", label);
        } else {
            let _ = write!(s, " {}={}%", label, (nibble as u16 * 10).min(100));
        }
    }

    /// NearbyInfo (0x10) action code / activity level (furiousMAC dissector).
    fn activity_name(code: u8) -> &'static str {
        match code {
            0x00 => "unknown",
            0x01 => "reporting-off",
            0x03 => "idle",
            0x05 => "audio (locked)",
            0x07 => "active (screen on)",
            0x09 => "screen+video",
            0x0A => "watch on wrist",
            0x0B => "recent interaction",
            0x0D => "driving",
            0x0E => "phone/FaceTime call",
            _    => "?",
        }
    }

    /// NearbyAction (0x0F) action type (furiousMAC dissector).
    fn action_name(t: u8) -> &'static str {
        match t {
            0x01 => "AppleTV Setup",
            0x04 => "Mobile Backup",
            0x05 => "Watch Setup",
            0x06 => "AppleTV Pair",
            0x07 => "Internet Relay",
            0x08 => "WiFi Password",
            0x09 => "iOS Setup",
            0x0A => "Repair",
            0x0B => "Speaker Setup",
            0x0C => "Apple Pay",
            0x0D => "Home Audio Setup",
            0x0E => "DevTools Pairing",
            0x0F => "Answered Call",
            0x10 => "Ended Call",
            0x11 => "DD Ping",
            0x12 => "DD Pong",
            0x13 => "Remote AutoFill",
            0x14 => "Companion Link",
            0x15 => "Remote Mgmt",
            0x16 => "Remote AutoFill Pong",
            0x17 => "Remote Display",
            _    => "?",
        }
    }
}
