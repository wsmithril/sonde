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
            // No Continuity message carries an empty body, so a zero-length
            // sub-message is trailing padding or salvage noise (in real captures
            // this shows up as tens of thousands of phantom `Apple ? (0x01)`
            // lines). Skip it rather than emit a phantom line.
            if mlen == 0 {
                i = end;
                continue;
            }
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
                    // NearbyInfo: high nibble of byte0 = status flags (bitmask), low
                    // nibble = activity code. byte1 = data flags, a rich bitmask
                    // (WiFi / Watch-lock / Auto-Unlock / AirPods). The bytes after
                    // that are a rotating authentication tag — 4 bytes when data-flag
                    // 0x02 is set, otherwise 3 — optionally followed by a post-auth
                    // byte on newer iPhones. Everything but the tag is plaintext; the
                    // tag is keyed (not decodable) and stays as the hex dump.
                    // Field layout per the FuriousMAC dissector / Cunche et al.
                    let sf = p[0] >> 4;
                    let ac = p[0] & 0x0F;
                    let _ = write!(s, "action={}(0x{:X}) flags[", Self::activity_name(ac), ac);
                    let mut sep = "";
                    if sf & 0x01 != 0 { let _ = write!(s, "{}primary", sep); sep = " "; }
                    if sf & 0x04 != 0 { let _ = write!(s, "{}airdrop", sep); }
                    let _ = write!(s, "]");
                    if p.len() > 1 {
                        let df = p[1];
                        let _ = write!(s, " df=0x{:02X}[", df);
                        let mut sep = "";
                        if df & 0x01 != 0 { let _ = write!(s, "{}airpods", sep); sep = " "; }
                        if df & 0x04 != 0 { let _ = write!(s, "{}wifi", sep); sep = " "; }
                        if df & 0x20 != 0 { let _ = write!(s, "{}watch-locked", sep); sep = " "; }
                        if df & 0x40 != 0 { let _ = write!(s, "{}autounlock-watch", sep); sep = " "; }
                        if df & 0x80 != 0 { let _ = write!(s, "{}autounlock", sep); }
                        let _ = write!(s, "]");
                        if p.len() > 2 {
                            let taglen = if df & 0x02 != 0 { 4 } else { 3 };
                            let avail = p.len() - 2;
                            if avail > taglen {
                                let _ = write!(s, " auth({}B) post=0x{:02X}", taglen, p[2 + taglen]);
                            } else {
                                let _ = write!(s, " auth({}B)", taglen.min(avail));
                            }
                            tail = Some((&p[2..], base + start + 2));
                        }
                    }
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
                0x03 if p.len() >= 22 => {
                    // AirPrint: address-type, resource-path-type, security-type, a
                    // TCP port (BE), a 16-byte IPv4/IPv6 address (plaintext leak) and
                    // measured power (furiousMAC). All plaintext.
                    let port = u16::from_be_bytes([p[3], p[4]]);
                    let _ = write!(s, "addr=0x{:02X} path=0x{:02X} sec=0x{:02X} port={} pwr={}dBm ip=",
                        p[0], p[1], p[2], port, p[21] as i8);
                    for (k, b) in p[5..21].iter().enumerate() {
                        let _ = write!(s, "{:02X}", b);
                        if k % 2 == 1 && k != 15 { let _ = write!(s, ":"); }
                    }
                }
                0x05 if p.len() >= 18 => {
                    // AirDrop: 8-byte prefix, version, then four 2-byte truncated
                    // SHA-256 hashes of the sender's AppleID / phone / e-mail /
                    // e-mail2 (not reversible) and a suffix. Decode the layout and
                    // which contact slots are populated.
                    let _ = write!(s,
                        "ver=0x{:02X} appleid={:02X}{:02X} phone={:02X}{:02X} email={:02X}{:02X} email2={:02X}{:02X}",
                        p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15], p[16]);
                }
                0x06 if p.len() >= 13 => {
                    // HomeKit accessory: status flags, 6-byte device ID, accessory
                    // category (LE), global-state number, config & compat version.
                    // Any trailing bytes are an encrypted/opaque field.
                    let cat = u16::from_le_bytes([p[7], p[8]]);
                    let gsn = u16::from_le_bytes([p[9], p[10]]);
                    // Status is the HAP "Status Flags" byte (same bits as the mDNS
                    // `sf` record): bit0 = not paired, bit1 = Wi-Fi not configured,
                    // bit2 = problem detected.
                    let _ = write!(s, "status=0x{:02X}[", p[0]);
                    let _ = write!(s, "{}", if p[0] & 0x01 != 0 { "unpaired " } else { "paired " });
                    if p[0] & 0x02 != 0 { let _ = write!(s, "no-wifi "); }
                    if p[0] & 0x04 != 0 { let _ = write!(s, "problem "); }
                    let _ = write!(s, "]");
                    let _ = write!(s,
                        " id={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} cat={}(0x{:04X}) gsn={} cfg={} ver={}",
                        p[1], p[2], p[3], p[4], p[5], p[6],
                        Self::homekit_category(cat), cat, gsn, p[11], p[12]);
                    if p.len() > 13 { tail = Some((&p[13..], base + start + 13)); }
                }
                0x08 if p.len() >= 7 => {
                    // Hey Siri: a perceptual hash of the voice command, SNR,
                    // confidence, a device class and a random byte (furiousMAC). All
                    // plaintext — the hash is a lossy fingerprint of the utterance.
                    let hash  = u16::from_be_bytes([p[0], p[1]]);
                    let class = u16::from_be_bytes([p[4], p[5]]);
                    let _ = write!(s, "hash=0x{:04X} snr={} conf={} class=0x{:04X} rnd=0x{:02X}",
                        hash, p[2], p[3], class, p[6]);
                }
                0x0B if p.len() >= 3 => {
                    // MagicSwitch (Apple Watch wrist detection): two opaque bytes plus
                    // a wrist-state confidence byte (0x3F = on wrist) (furiousMAC).
                    let _ = write!(s, "data=0x{:02X}{:02X} wrist={}", p[0], p[1],
                        if p[2] == 0x3F { "on-wrist" } else { "off" });
                    if p[2] != 0x3F { let _ = write!(s, "(0x{:02X})", p[2]); }
                }
                0x0D if p.len() >= 4 => {
                    // Tethering Target: a 4-byte identifier derived from the user's
                    // iCloud DSID. Rotates ~daily but is identical across every device
                    // on the same iCloud account — a cross-device correlator.
                    let _ = write!(s, "icloud-id={:02X}{:02X}{:02X}{:02X}", p[0], p[1], p[2], p[3]);
                    if p.len() > 4 { tail = Some((&p[4..], base + start + 4)); }
                }
                0x0E if p.len() >= 6 => {
                    // Tethering Source (Instant Hotspot): version, flags, battery %,
                    // cellular connection type and signal-quality bars — all plaintext
                    // (furiousMAC). A phone broadcasting its own battery and carrier.
                    let cell = u16::from_le_bytes([p[3], p[4]]);
                    let _ = write!(s, "ver=0x{:02X} flags=0x{:02X} batt={}% cell={} bars={}",
                        p[0], p[1], p[2], Self::cell_type(cell), p[5]);
                    if p.len() > 6 { tail = Some((&p[6..], base + start + 6)); }
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
        // Model IDs verified against the d4rken-org/capod device tables. The high
        // byte identifies the product; the low byte 0x20 marks the Apple audio
        // vendor. Kept current through AirPods Pro 3 / AirPods 4 (2024–25).
        match m {
            // AirPods
            0x0220 => "AirPods (1st gen)",
            0x0F20 => "AirPods (2nd gen)",
            0x1320 => "AirPods (3rd gen)",
            0x1920 => "AirPods (4th gen)",
            0x1B20 => "AirPods (4th gen, ANC)",
            0x0E20 => "AirPods Pro",
            0x1420 => "AirPods Pro (2nd gen)",
            0x2420 => "AirPods Pro (2nd gen, USB-C)",
            0x2720 => "AirPods Pro (3rd gen)",
            0x0A20 => "AirPods Max",
            0x1F20 => "AirPods Max (USB-C)",
            0x2D20 => "AirPods Max (USB-C, 2024)",
            // Beats
            0x0320 => "Powerbeats 3",
            0x0520 => "BeatsX",
            0x0620 => "Beats Solo 3",
            0x0920 => "Beats Studio 3",
            0x0B20 => "Powerbeats Pro",
            0x0C20 => "Beats Solo Pro",
            0x0D20 => "Powerbeats 4",
            0x1020 => "Beats Flex",
            0x1120 => "Beats Studio Buds",
            0x1220 => "Beats Fit Pro",
            0x1620 => "Beats Studio Buds+",
            0x1720 => "Beats Studio Pro",
            0x1D20 => "Powerbeats Pro 2",
            0x2520 => "Beats Solo 4",
            0x2620 => "Beats Solo Buds",
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

    /// HomeKit accessory category (HAP "Accessory Categories", subset).
    fn homekit_category(c: u16) -> &'static str {
        match c {
            0x0001 => "Other",
            0x0002 => "Bridge",
            0x0003 => "Fan",
            0x0004 => "Garage",
            0x0005 => "Lightbulb",
            0x0006 => "Door Lock",
            0x0007 => "Outlet",
            0x0008 => "Switch",
            0x0009 => "Thermostat",
            0x000A => "Sensor",
            0x000B => "Security System",
            0x000C => "Door",
            0x000D => "Window",
            0x000E => "Window Covering",
            0x000F => "Programmable Switch",
            0x0010 => "Range Extender",
            0x0011 => "IP Camera",
            0x0012 => "Video Doorbell",
            0x0013 => "Air Purifier",
            0x0014 => "Heater",
            0x0015 => "Air Conditioner",
            0x0016 => "Humidifier",
            0x0017 => "Dehumidifier",
            0x001C => "Sprinkler",
            0x001D => "Faucet",
            0x001E => "Shower System",
            0x0020 => "Television",
            0x0021 => "Remote Control",
            _      => "?",
        }
    }

    /// Instant Hotspot cellular connection type (furiousMAC dissector).
    fn cell_type(t: u16) -> &'static str {
        match t {
            0 => "GSM", 1 => "1xRTT", 2 => "GPRS", 3 => "EDGE",
            4 => "EV-DO", 5 => "3G", 6 => "4G", 7 => "LTE",
            _ => "?",
        }
    }
}
