//! Attribute Protocol, L2CAP CID 0x0004 (Core v5.4 Vol 3 Part F).
//!
//! Every ATT PDU is an opcode followed by method-specific parameters. Bit 6 of
//! the opcode marks a Command (no response expected) and bit 7 an authentication
//! signature; the method is the low six bits, so `0x52` is a Write Command and
//! `0xD2` a signed one.
//!
//! Discovery responses — Find Information, Read By Type, Read By Group Type —
//! are lists of fixed-width records whose width is given by a leading length
//! byte. Walking that list is what turns a service-discovery capture into a
//! handle map, so those arms print each record rather than the length alone.

use core::fmt::Write;

use super::{line, send, u16le, write_hex_capped, Decoder};

pub struct Att;

impl Decoder<u16> for Att {
    fn keys(&self) -> &'static [u16] {
        &[0x0004]
    }

    fn decode(&self, d: &[u8]) {
        let op = d[0];
        let n = Self::name(op);
        let flags = match (op & 0x40 != 0, op & 0x80 != 0) {
            (true, true) => " [signed-cmd]",
            (true, false) => " [cmd]",
            (false, true) => " [signed]",
            _ => "",
        };
        match op & 0x3F {
            // Error Rsp: which request failed, on which handle, and why.
            0x01 if d.len() >= 5 => crate::ulogf!(
                "  ATT 0x{:02X} {} on=0x{:02X} ({}) handle=0x{:04X} err=0x{:02X} ({})\r\n",
                op, n, d[1], Self::name(d[1]), u16le(d, 2), d[4],
                crate::central::att_error_name(d[4])),
            0x02 | 0x03 if d.len() >= 3 => crate::ulogf!(
                "  ATT 0x{:02X} {} mtu={}\r\n", op, n, u16le(d, 1)),
            // Find Information / Read By Type / Read By Group Type requests:
            // handle range, and for the latter two an attribute type UUID.
            0x04 | 0x08 | 0x10 if d.len() >= 5 => {
                let mut s = line();
                let _ = write!(
                    s, "ATT 0x{:02X} {} handles=0x{:04X}..0x{:04X}",
                    op, n, u16le(d, 1), u16le(d, 3)
                );
                if d.len() > 5 {
                    let _ = s.push_str(" type=");
                    Self::write_uuid(&mut s, &d[5..]);
                }
                send(s);
            }
            // Find Information Rsp: a format byte (1 = 16-bit UUIDs, 2 =
            // 128-bit) then handle/UUID pairs of the matching width.
            0x05 if d.len() >= 2 => {
                let uw = if d[1] == 2 { 16 } else { 2 };
                crate::ulogf!(
                    "  ATT 0x{:02X} {} format={} ({}-bit UUIDs)\r\n", op, n, d[1], uw * 8);
                for rec in d[2..].chunks_exact(2 + uw) {
                    let mut s = line();
                    let _ = write!(s, "  h=0x{:04X} uuid=", u16le(rec, 0));
                    Self::write_uuid(&mut s, &rec[2..]);
                    send(s);
                }
            }
            // Find By Type Value Req: handle range, the attribute type being
            // matched (a 16-bit UUID, in practice 0x2800 Primary Service), and
            // the value to match — which for that type is the 128-bit service
            // UUID the peer is looking for.
            0x06 if d.len() >= 7 => {
                let mut s = line();
                let _ = write!(
                    s, "ATT 0x{:02X} {} handles=0x{:04X}..0x{:04X} type=",
                    op, n, u16le(d, 1), u16le(d, 3)
                );
                Self::write_uuid(&mut s, &d[5..7]);
                send(s);
                if d.len() > 7 {
                    let mut s = line();
                    let _ = s.push_str("  value=");
                    Self::write_uuid(&mut s, &d[7..]);
                    send(s);
                }
            }
            // Find By Type Value Rsp: the handle ranges that matched.
            0x07 if d.len() >= 5 => {
                crate::ulogf!("  ATT 0x{:02X} {} ranges={}\r\n", op, n, (d.len() - 1) / 4);
                for rec in d[1..].chunks_exact(4) {
                    let mut s = line();
                    let _ = write!(s, "  0x{:04X}..0x{:04X}", u16le(rec, 0), u16le(rec, 2));
                    send(s);
                }
            }
            // Read By Type Rsp: a length byte, then that many bytes per record —
            // handle followed by the attribute value. For a 0x2803 scan the
            // value is properties + value handle + UUID, which is the
            // characteristic map of the peer.
            0x09 if d.len() >= 2 && d[1] as usize >= 2 => {
                let w = d[1] as usize;
                crate::ulogf!(
                    "  ATT 0x{:02X} {} reclen={} records={}\r\n", op, n, w, (d.len() - 2) / w);
                for rec in d[2..].chunks_exact(w) {
                    let mut s = line();
                    let _ = write!(s, "  h=0x{:04X} value=", u16le(rec, 0));
                    write_hex_capped(&mut s, &rec[2..], 32);
                    send(s);
                }
            }
            // Read By Group Type Rsp: same shape, with an end-of-group handle
            // between the start handle and the value.
            0x11 if d.len() >= 2 && d[1] as usize >= 4 => {
                let w = d[1] as usize;
                crate::ulogf!(
                    "  ATT 0x{:02X} {} reclen={} groups={}\r\n", op, n, w, (d.len() - 2) / w);
                for rec in d[2..].chunks_exact(w) {
                    let mut s = line();
                    let _ = write!(s, "  0x{:04X}..0x{:04X} uuid=", u16le(rec, 0), u16le(rec, 2));
                    Self::write_uuid(&mut s, &rec[4..]);
                    send(s);
                }
            }
            // Read Req / Read Blob Req: the handle, plus where in the value to
            // resume for a blob.
            0x0A | 0x0C if d.len() >= 3 => {
                let mut s = line();
                let _ = write!(s, "ATT 0x{:02X} {} handle=0x{:04X}", op, n, u16le(d, 1));
                if (op & 0x3F) == 0x0C && d.len() >= 5 {
                    let _ = write!(s, " offset={}", u16le(d, 3));
                }
                send(s);
            }
            // Read Rsp / Read Blob Rsp: a bare value. The handle came from the
            // request, so only the bytes are new.
            0x0B | 0x0D if d.len() >= 2 => {
                let mut s = line();
                let _ = write!(s, "ATT 0x{:02X} {} vlen={} value=", op, n, d.len() - 1);
                write_hex_capped(&mut s, &d[1..], 32);
                send(s);
                crate::device::midea::gatt::frame(&d[1..]);
                crate::device::daikin::gatt::frame(&d[1..]);
            }
            // Write Req / Write Cmd / Notification / Indication: handle + value.
            0x12 | 0x1B | 0x1D if d.len() >= 3 => {
                let mut s = line();
                let _ = write!(
                    s, "ATT 0x{:02X} {}{} handle=0x{:04X} vlen={} value=",
                    op, n, flags, u16le(d, 1), d.len() - 3
                );
                write_hex_capped(&mut s, &d[3..], 32);
                send(s);
                crate::device::midea::gatt::frame(&d[3..]);
                crate::device::daikin::gatt::frame(&d[3..]);
            }
            // Prepare Write Req / Rsp: handle, offset into the value, and the
            // part being queued.
            0x16 | 0x17 if d.len() >= 5 => {
                let mut s = line();
                let _ = write!(
                    s, "ATT 0x{:02X} {} handle=0x{:04X} offset={} vlen={} value=",
                    op, n, u16le(d, 1), u16le(d, 3), d.len() - 5
                );
                write_hex_capped(&mut s, &d[5..], 32);
                send(s);
            }
            // Execute Write Req: commit or discard everything queued so far.
            0x18 if d.len() >= 2 => crate::ulogf!(
                "  ATT 0x{:02X} {} flags={} ({})\r\n",
                op, n, d[1], if d[1] == 0 { "cancel" } else { "write" }),
            // Read Multiple / Read Multiple Variable Req: a plain handle list.
            0x0E | 0x20 if d.len() >= 3 => {
                let mut s = line();
                let _ = write!(s, "ATT 0x{:02X} {} handles=", op, n);
                for (i, rec) in d[1..].chunks_exact(2).enumerate() {
                    if i > 0 {
                        let _ = s.push(',');
                    }
                    let _ = write!(s, "0x{:04X}", u16le(rec, 0));
                }
                send(s);
            }
            _ => crate::ulogf!("  ATT 0x{:02X} {}{} len={}\r\n", op, n, flags, d.len()),
        }
    }
}

/// Method names and the UUID rendering the ATT arms share.
impl Att {
    /// ATT method names, keyed on the low six opcode bits.
    fn name(op: u8) -> &'static str {
        match op & 0x3F {
            0x01 => "Error Rsp",
            0x02 => "Exchange MTU Req",
            0x03 => "Exchange MTU Rsp",
            0x04 => "Find Information Req",
            0x05 => "Find Information Rsp",
            0x06 => "Find By Type Value Req",
            0x07 => "Find By Type Value Rsp",
            0x08 => "Read By Type Req",
            0x09 => "Read By Type Rsp",
            0x0A => "Read Req",
            0x0B => "Read Rsp",
            0x0C => "Read Blob Req",
            0x0D => "Read Blob Rsp",
            0x0E => "Read Multiple Req",
            0x0F => "Read Multiple Rsp",
            0x10 => "Read By Group Type Req",
            0x11 => "Read By Group Type Rsp",
            0x12 => "Write Req",
            0x13 => "Write Rsp",
            0x16 => "Prepare Write Req",
            0x17 => "Prepare Write Rsp",
            0x18 => "Execute Write Req",
            0x19 => "Execute Write Rsp",
            0x1B => "Handle Value Notification",
            0x1D => "Handle Value Indication",
            0x1E => "Handle Value Confirmation",
            0x20 => "Read Multiple Variable Req",
            0x21 => "Read Multiple Variable Rsp",
            0x23 => "Multiple Handle Value Notification",
            _ => "?",
        }
    }

    /// The 128-bit UUID base that 16-bit and 32-bit SIG UUIDs expand into.
    const SIG_BASE: [u8; 16] = [
        0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Names for known vendor 128-bit UUIDs the SIG DB does not carry. Written
    /// most-significant-byte-first (as the UUID string reads); matched against the
    /// little-endian on-air bytes, so only these exact UUIDs are ever named.
    ///
    /// Sony camera BLE remote-control service + characteristics, reverse-engineered
    /// by the freemote project (https://github.com/coral/freemote, BLECamera.cpp).
    /// The characteristics are the 128-bit forms on the service's base; a camera
    /// that instead exposes bare 16-bit 0xFF01/0xFF02 simply won't match here.
    ///
    /// Jabra Elite 10 (Gen 2) orientation service + notify characteristics, from
    /// the jabra-elite10-re project (https://git.pg.edu.pl/p829296/jabra-elite10-re,
    /// docs/PROTOCOL.md). Discovery/enumeration is observable even though the
    /// notifies themselves are gated behind authentication.
    const KNOWN_UUID128: &'static [([u8; 16], &'static str)] = &[
        ([0x80, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
         "Sony Camera Remote Control"),
        ([0x80, 0x00, 0xFF, 0x01, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
         "Sony Camera: remote command"),
        ([0x80, 0x00, 0xFF, 0x02, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
         "Sony Camera: remote notify"),
        ([0x20, 0x23, 0x12, 0x19, 0x17, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
         "Jabra Elite 10 orientation service"),
        ([0x20, 0x23, 0x12, 0x19, 0x17, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
         "Jabra Elite 10: orientation notify"),
        ([0x20, 0x23, 0x12, 0x19, 0x17, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
         "Jabra Elite 10: orientation/state notify"),
        // Common vendor GATT services + characteristics, from the community
        // registry NordicSemiconductor/bluetooth-numbers-database (BSD-3). A
        // curated high-prevalence subset (Nordic UART / DFU / SMP, Apple ANCS/AMS,
        // Hue, TI OAD, LEGO) — the rest of its ~250 entries are niche.
        ([0x6E, 0x40, 0x00, 0x01, 0xB5, 0xA3, 0xF3, 0x93, 0xE0, 0xA9, 0xE5, 0x0E, 0x24, 0xDC, 0xCA, 0x9E],
         "Nordic UART Service (NUS)"),
        ([0x00, 0x00, 0x15, 0x23, 0x12, 0x12, 0xEF, 0xDE, 0x15, 0x23, 0x78, 0x5F, 0xEA, 0xBC, 0xD1, 0x23],
         "Nordic LED and Button Service"),
        ([0x00, 0x00, 0x15, 0x30, 0x12, 0x12, 0xEF, 0xDE, 0x15, 0x23, 0x78, 0x5F, 0xEA, 0xBC, 0xD1, 0x23],
         "Nordic Legacy DFU Service"),
        ([0x8E, 0x40, 0x00, 0x01, 0xF3, 0x15, 0x4F, 0x60, 0x9F, 0xB8, 0x83, 0x88, 0x30, 0xDA, 0xEA, 0x50],
         "Nordic Buttonless DFU Service"),
        ([0x8D, 0x53, 0xDC, 0x1D, 0x1D, 0xB7, 0x4C, 0xD3, 0x86, 0x8B, 0x8A, 0x52, 0x74, 0x60, 0xAA, 0x84],
         "SMP / mcumgr Service"),
        ([0x14, 0x38, 0x78, 0x00, 0x13, 0x0C, 0x49, 0xE7, 0xB8, 0x77, 0x28, 0x81, 0xC8, 0x9C, 0xB2, 0x58],
         "Nordic Wi-Fi Provisioning Service"),
        ([0x79, 0x05, 0xF4, 0x31, 0xB5, 0xCE, 0x4E, 0x99, 0xA4, 0x0F, 0x4B, 0x1E, 0x12, 0x2D, 0x00, 0xD0],
         "Apple Notification Center (ANCS)"),
        ([0x89, 0xD3, 0x50, 0x2B, 0x0F, 0x36, 0x43, 0x3A, 0x8E, 0xF4, 0xC5, 0x02, 0xAD, 0x55, 0xF8, 0xDC],
         "Apple Media Service (AMS)"),
        ([0x93, 0x2C, 0x32, 0xBD, 0x00, 0x00, 0x47, 0xA2, 0x83, 0x5A, 0xA8, 0xD4, 0x55, 0xB8, 0x59, 0xDD],
         "Philips Hue Light Control"),
        ([0xB8, 0x84, 0x3A, 0xDD, 0x00, 0x00, 0x4A, 0xA1, 0x87, 0x94, 0xC3, 0xF4, 0x62, 0x03, 0x0B, 0xDA],
         "Philips Hue Light Update"),
        ([0xF0, 0x00, 0xFF, 0xC0, 0x04, 0x51, 0x40, 0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
         "TI OAD (OTA) Service"),
        ([0xA3, 0xC8, 0x75, 0x00, 0x8E, 0xD3, 0x4B, 0xDF, 0x8A, 0x39, 0xA0, 0x1B, 0xEB, 0xED, 0xE2, 0x95],
         "Eddystone Configuration Service"),
        ([0x00, 0x00, 0x16, 0x23, 0x12, 0x12, 0xEF, 0xDE, 0x16, 0x23, 0x78, 0x5F, 0xEA, 0xBC, 0xD1, 0x23],
         "LEGO Wireless Protocol v3 Hub"),
        ([0x00, 0x00, 0x16, 0x25, 0x12, 0x12, 0xEF, 0xDE, 0x16, 0x23, 0x78, 0x5F, 0xEA, 0xBC, 0xD1, 0x23],
         "LEGO Wireless Protocol v3 Bootloader"),
        ([0x6E, 0x40, 0x00, 0x02, 0xB5, 0xA3, 0xF3, 0x93, 0xE0, 0xA9, 0xE5, 0x0E, 0x24, 0xDC, 0xCA, 0x9E],
         "Nordic UART: RX (write)"),
        ([0x6E, 0x40, 0x00, 0x03, 0xB5, 0xA3, 0xF3, 0x93, 0xE0, 0xA9, 0xE5, 0x0E, 0x24, 0xDC, 0xCA, 0x9E],
         "Nordic UART: TX (notify)"),
        ([0x00, 0x00, 0x15, 0x31, 0x12, 0x12, 0xEF, 0xDE, 0x15, 0x23, 0x78, 0x5F, 0xEA, 0xBC, 0xD1, 0x23],
         "Legacy DFU: control point"),
        ([0x00, 0x00, 0x15, 0x32, 0x12, 0x12, 0xEF, 0xDE, 0x15, 0x23, 0x78, 0x5F, 0xEA, 0xBC, 0xD1, 0x23],
         "Legacy DFU: packet"),
        ([0x8E, 0xC9, 0x00, 0x01, 0xF3, 0x15, 0x4F, 0x60, 0x9F, 0xB8, 0x83, 0x88, 0x30, 0xDA, 0xEA, 0x50],
         "DFU: control point"),
        ([0x8E, 0xC9, 0x00, 0x03, 0xF3, 0x15, 0x4F, 0x60, 0x9F, 0xB8, 0x83, 0x88, 0x30, 0xDA, 0xEA, 0x50],
         "Buttonless DFU (no bonds)"),
        ([0xDA, 0x2E, 0x78, 0x28, 0xFB, 0xCE, 0x4E, 0x01, 0xAE, 0x9E, 0x26, 0x11, 0x74, 0x99, 0x7C, 0x48],
         "SMP / mcumgr characteristic"),
        // Google Fast Pair characteristics, on service 0xFE2C (named "Google LLC"
        // by the SIG member table). These are the most common vendor 128-bit UUIDs
        // seen on modern earbuds/accessories; the remaining Fast Pair chars on the
        // same base are named generically by KNOWN_BASE128 below.
        ([0xFE, 0x2C, 0x12, 0x33, 0x83, 0x66, 0x48, 0x14, 0x8E, 0xB0, 0x01, 0xDE, 0x32, 0x10, 0x0B, 0xEA],
         "Google Fast Pair: Model ID"),
        ([0xFE, 0x2C, 0x12, 0x34, 0x83, 0x66, 0x48, 0x14, 0x8E, 0xB0, 0x01, 0xDE, 0x32, 0x10, 0x0B, 0xEA],
         "Google Fast Pair: Key-based Pairing"),
        ([0xFE, 0x2C, 0x12, 0x35, 0x83, 0x66, 0x48, 0x14, 0x8E, 0xB0, 0x01, 0xDE, 0x32, 0x10, 0x0B, 0xEA],
         "Google Fast Pair: Passkey"),
        ([0xFE, 0x2C, 0x12, 0x36, 0x83, 0x66, 0x48, 0x14, 0x8E, 0xB0, 0x01, 0xDE, 0x32, 0x10, 0x0B, 0xEA],
         "Google Fast Pair: Account Key"),
        ([0xFE, 0x2C, 0x12, 0x37, 0x83, 0x66, 0x48, 0x14, 0x8E, 0xB0, 0x01, 0xDE, 0x32, 0x10, 0x0B, 0xEA],
         "Google Fast Pair: Additional Data"),
    ];

    /// Known vendor 128-bit UUID *bases*: the fixed low 12 bytes (bytes 4..16 of
    /// the UUID read most-significant-first) that a vendor builds a whole family
    /// of proprietary UUIDs on, varying only the top 32 bits. Matched when no
    /// exact [`Self::KNOWN_UUID128`] entry does, so one row names every service
    /// and characteristic in the family; the varying prefix is printed alongside.
    ///
    /// Garmin bases and the Google Fast Pair base cover the wearable/earbud
    /// devices whose per-characteristic UUIDs are too numerous to list. The
    /// Garmin bases are re-derived from the GFDI protocol notes (gadgetbridge.org)
    /// and observed captures; no third-party code is used.
    const KNOWN_BASE128: &'static [([u8; 12], &'static str)] = &[
        ([0x83, 0x66, 0x48, 0x14, 0x8E, 0xB0, 0x01, 0xDE, 0x32, 0x10, 0x0B, 0xEA], "Google Fast Pair"),
        ([0xD1, 0x02, 0x11, 0xE1, 0x9B, 0x23, 0x00, 0x02, 0x5B, 0x00, 0xA5, 0xA5], "Garmin"),
        ([0x66, 0x7B, 0x11, 0xE3, 0x94, 0x9A, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66], "Garmin GFDI"),
    ];

    /// Append a UUID given as it appears on air (little-endian, 2 or 16 bytes).
    ///
    /// A 128-bit UUID built on the SIG base is printed as the short form it stands
    /// for, so a peer that spells out `0000180F-0000-1000-8000-00805F9B34FB` reads
    /// the same as one that sent `0x180F`. Anything else prints in canonical
    /// most-significant-first form, which is how vendors document their own UUIDs.
    fn write_uuid(s: &mut crate::LogLine, u: &[u8]) {
        if u.len() == 2 {
            Self::write_uuid16(s, u16le(u, 0));
            return;
        }
        if u.len() != 16 {
            write_hex_capped(s, u, 16);
            return;
        }
        if u[..12] == Self::SIG_BASE[..12] && u[14..] == Self::SIG_BASE[14..] {
            Self::write_uuid16(s, u16le(u, 12));
            return;
        }
        for (i, b) in u.iter().rev().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                let _ = s.push('-');
            }
            let _ = write!(s, "{:02X}", b);
        }
        if let Some(n) = Self::uuid128_name(u) {
            let _ = write!(s, " ({})", n);
        } else if let Some((n, prefix)) = Self::uuid128_base_name(u) {
            let _ = write!(s, " ({} [{:08X}])", n, prefix);
        } else if u.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count() >= 12 {
            // Some vendors pack a printable identifier into the 128 bits (e.g.
            // "…excelpoint.com", "CHAR-…BLE"). Surface the ASCII reading (MSB-first,
            // matching the display order) when the UUID is mostly printable.
            let _ = s.push_str(" \"");
            for &b in u.iter().rev() {
                let _ = s.push(if (0x20..=0x7E).contains(&b) { b as char } else { '.' });
            }
            let _ = s.push('"');
        }
    }

    /// Append a 16-bit UUID and its assigned-number name, when it has one.
    fn write_uuid16(s: &mut crate::LogLine, id: u16) {
        let _ = write!(s, "0x{:04X}", id);
        if let Some(n) = crate::decoder::uuid_name(id) {
            let _ = write!(s, " ({})", n);
        }
    }

    /// Name for a known vendor 128-bit UUID, if any. `u` is the little-endian
    /// on-air form; [`Self::KNOWN_UUID128`] is most-significant-byte-first.
    fn uuid128_name(u: &[u8]) -> Option<&'static str> {
        Self::KNOWN_UUID128
            .iter()
            .find_map(|(msb, name)| u.iter().rev().eq(msb.iter()).then_some(*name))
    }

    /// Vendor name and the varying 32-bit prefix for a UUID built on a known
    /// vendor base. `u` is the little-endian on-air form; a base in
    /// [`Self::KNOWN_BASE128`] is the fixed low 12 bytes most-significant-first,
    /// so it matches the reverse of `u[..12]`. The prefix is the top 32 bits
    /// (`u[12..16]` read most-significant-first) — the part that names the
    /// specific service or characteristic within the vendor's family.
    fn uuid128_base_name(u: &[u8]) -> Option<(&'static str, u32)> {
        Self::KNOWN_BASE128.iter().find_map(|(base, name)| {
            u[..12]
                .iter()
                .rev()
                .eq(base.iter())
                .then(|| (*name, u32::from_be_bytes([u[15], u[14], u[13], u[12]])))
        })
    }
}
