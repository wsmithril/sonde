//! Bluetooth Mesh advertising service data (Mesh Profile / Protocol spec).
//!
//! `0x1828` **Mesh Proxy Service** — a Proxy Server advertises its identity so a
//! GATT client can find a node on a subnet: a 1-byte Identification Type followed
//! by a Network ID (8 B) or Node Identity (hash 8 B + random 8 B). Mesh 1.1 adds
//! the "private" variants.
//!
//! `0x1827` **Mesh Provisioning Service** — an unprovisioned device beacons a
//! 16-byte Device UUID + 2-byte OOB Information bitfield so a Provisioner can add
//! it to a network. Both are fully spec-defined plaintext (no vendor guessing).
//!
//! Mesh also has its own **advertising bearer** AD types, decoded by the free
//! functions at the bottom of this module: `0x2B` Mesh Beacon, `0x2A` Mesh
//! Message (a Network PDU) and `0x29` PB-ADV (provisioning over advertising).
//! Network PDUs are encrypted and obfuscated bar their first octet; beacons and
//! PB-ADV headers are plaintext.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Bluetooth Mesh — Proxy (UUID 0x1828) and Provisioning (UUID 0x1827) service
/// data; dispatched by UUID.
pub(super) struct BtMesh;
impl super::VendorDecoder for BtMesh {
    fn service_uuids(&self) -> &'static [u16] { &[0x1827, 0x1828] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        match ctx.key {
            0x1827 => Self::decode_provisioning(body, ctx.base),
            _ => Self::decode_proxy(body, ctx.base),
        }
    }
}

impl BtMesh {
    /// Mesh Proxy Service ADV: `[Identification Type][data]`.
    fn decode_proxy(f: &[u8], base: usize) {
        if f.is_empty() { return; }
        let mut s: LogStr = LogStr::new();
        match f[0] {
            0x00 if f.len() >= 9 => {
                // Network ID (identifies the subnet, stable per net-key).
                let _ = write!(s, "    Mesh Proxy: Network ID ");
                write_hex(&mut s, &f[1..9]);
            }
            0x01 if f.len() >= 17 => {
                // Node Identity: 8-byte hash + 8-byte random (rotates per spec).
                let _ = write!(s, "    Mesh Proxy: Node Identity hash=");
                write_hex(&mut s, &f[1..9]);
                let _ = write!(s, " rnd=");
                write_hex(&mut s, &f[9..17]);
            }
            0x02 if f.len() >= 9 => {
                // Mesh 1.1 privacy variant of Network ID.
                let _ = write!(s, "    Mesh Proxy: Private Network ID ");
                write_hex(&mut s, &f[1..]);
            }
            0x03 => {
                let _ = write!(s, "    Mesh Proxy: Private Node Identity ");
                write_hex(&mut s, &f[1..]);
            }
            t => {
                let _ = write!(s, "    Mesh Proxy: type=0x{:02X} (?) len={}", t, f.len() - 1);
                emit(s);
                hexdump(&f[1..], base + 1, 6);
                return;
            }
        }
        emit(s);
    }

    /// Mesh Provisioning Service ADV: `[Device UUID:16][OOB Information:2 (BE)]`.
    fn decode_provisioning(f: &[u8], base: usize) {
        if f.len() < 16 {
            let mut s: LogStr = LogStr::new();
            let _ = write!(s, "    Mesh Provisioning: short len={}", f.len());
            emit(s);
            hexdump(f, base, 6);
            return;
        }
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Mesh Provisioning: DeviceUUID=");
        for (k, b) in f[..16].iter().enumerate() {
            let _ = write!(s, "{:02X}", b);
            if matches!(k, 3 | 5 | 7 | 9) { let _ = write!(s, "-"); }
        }
        if f.len() >= 18 {
            // OOB Information is a 16-bit bitfield (transmitted big-endian).
            let oob = u16::from_be_bytes([f[16], f[17]]);
            let _ = write!(s, " oob=0x{:04X}", oob);
            Self::write_oob(&mut s, oob);
        }
        emit(s);
    }

    /// Append the set OOB Information bits (Mesh Profile §3.10.3) as short names.
    fn write_oob(s: &mut LogStr, bits: u16) {
        const NAMES: [(u16, &str); 9] = [
            (0, "Other"), (1, "URI"), (2, "2D-code"), (3, "barcode"),
            (4, "NFC"), (5, "number"), (6, "string"), (7, "cert"), (8, "records"),
        ];
        let mut first = true;
        for (bit, name) in NAMES {
            if bits & (1 << bit) != 0 {
                let _ = write!(s, "{}{}", if first { " [" } else { "," }, name);
                first = false;
            }
        }
        // Bits 11..15 flag where the OOB value is physically printed.
        const LOC: [(u16, &str); 5] = [
            (11, "on-box"), (12, "in-box"), (13, "on-paper"), (14, "in-manual"), (15, "on-device"),
        ];
        for (bit, name) in LOC {
            if bits & (1 << bit) != 0 {
                let _ = write!(s, "{}{}", if first { " [" } else { "," }, name);
                first = false;
            }
        }
        if !first { let _ = write!(s, "]"); }
    }
}

// ── Mesh advertising bearer AD types ─────────────────────────────────────────

/// Mesh Beacon (AD 0x2B): `[Beacon Type][Beacon Data]`.
///
/// * `0x00` Unprovisioned Device Beacon — Device UUID (16 B) + OOB Information
///   (2 B, big-endian) + an optional URI Hash (4 B). All plaintext: this is a
///   device asking to be provisioned, and its Device UUID is a permanent
///   identifier that no address rotation hides.
/// * `0x01` Secure Network Beacon — Flags (1 B) + Network ID (8 B) + IV Index
///   (4 B, big-endian) + Authentication Value (8 B). The Network ID names the
///   subnet and is stable for the life of the net-key.
/// * `0x02` Mesh Private Beacon — Random (13 B) + obfuscated beacon data (5 B) +
///   Authentication tag (8 B); the Mesh 1.1 replacement that hides the fields
///   above behind the random.
pub fn decode_beacon(f: &[u8]) {
    if f.is_empty() { return; }
    let mut s: LogStr = LogStr::new();
    match f[0] {
        0x00 if f.len() >= 19 => {
            let _ = write!(s, "    Mesh Beacon: Unprovisioned DeviceUUID=");
            for (k, b) in f[1..17].iter().enumerate() {
                let _ = write!(s, "{:02X}", b);
                if matches!(k, 3 | 5 | 7 | 9) { let _ = write!(s, "-"); }
            }
            let oob = u16::from_be_bytes([f[17], f[18]]);
            let _ = write!(s, " oob=0x{:04X}", oob);
            BtMesh::write_oob(&mut s, oob);
            if f.len() >= 23 {
                let _ = write!(s, " urihash=");
                write_hex(&mut s, &f[19..23]);
            }
        }
        0x01 if f.len() >= 22 => {
            // Flags bit 0 = Key Refresh in progress, bit 1 = IV Update in progress.
            let _ = write!(s, "    Mesh Beacon: SecureNetwork flags=0x{:02X}", f[1]);
            if f[1] & 0x01 != 0 { let _ = write!(s, " key-refresh"); }
            if f[1] & 0x02 != 0 { let _ = write!(s, " iv-update"); }
            let _ = write!(s, " netid=");
            write_hex(&mut s, &f[2..10]);
            let _ = write!(s, " iv={} auth=", u32::from_be_bytes([f[10], f[11], f[12], f[13]]));
            write_hex(&mut s, &f[14..22]);
        }
        0x02 if f.len() >= 27 => {
            let _ = write!(s, "    Mesh Beacon: Private random=");
            write_hex(&mut s, &f[1..14]);
            let _ = write!(s, " obfuscated=");
            write_hex(&mut s, &f[14..19]);
            let _ = write!(s, " tag=");
            write_hex(&mut s, &f[19..27]);
        }
        t => {
            let _ = write!(s, "    Mesh Beacon: type=0x{:02X} (?) len={}", t, f.len() - 1);
        }
    }
    emit(s);
}

/// Mesh Message (AD 0x2A) — a Network PDU. Only the first octet is in the
/// clear: IVI (bit 7, the low bit of the IV Index in use) and NID (bits 6..0, a
/// 7-bit tag derived from the net-key that says which subnet this belongs to).
/// The next 6 octets are obfuscated (CTL, TTL, SEQ, SRC) and the rest is
/// encrypted DST + Transport PDU + NetMIC, which the caller's hexdump carries.
pub fn decode_message(f: &[u8]) {
    if f.is_empty() { return; }
    let mut s: LogStr = LogStr::new();
    let _ = write!(s, "    Mesh Message: ivi={} nid=0x{:02X} obfuscated+encrypted len={}",
        f[0] >> 7, f[0] & 0x7F, f.len() - 1);
    emit(s);
}

/// PB-ADV (AD 0x29) — provisioning carried over advertising:
/// `[Link ID:4 BE][Transaction Number:1][Generic Provisioning PDU]`. The GPCF
/// in the low two bits of the first Generic Provisioning octet selects the PDU
/// form; a Link Open carries the target's 16-byte Device UUID in the clear.
pub fn decode_pb_adv(f: &[u8]) {
    if f.len() < 6 { return; }
    let mut s: LogStr = LogStr::new();
    let _ = write!(s, "    PB-ADV: link=0x{:08X} txn={} ",
        u32::from_be_bytes([f[0], f[1], f[2], f[3]]), f[4]);
    let g = f[5];
    match g & 0x03 {
        0x00 => {
            // Transaction Start: SegN (last segment index) | GPCF, then the
            // reassembled length (2 B BE) and a checksum over it.
            let _ = write!(s, "TransactionStart segn={}", g >> 2);
            if f.len() >= 9 {
                let _ = write!(s, " total={} fcs=0x{:02X}",
                    u16::from_be_bytes([f[6], f[7]]), f[8]);
            }
        }
        0x01 => { let _ = write!(s, "TransactionAck"); }
        0x02 => { let _ = write!(s, "TransactionContinuation seg={}", g >> 2); }
        _ => {
            // Bearer control: the opcode occupies the upper 6 bits.
            match g >> 2 {
                0x00 => {
                    let _ = write!(s, "LinkOpen DeviceUUID=");
                    if f.len() >= 22 {
                        for (k, b) in f[6..22].iter().enumerate() {
                            let _ = write!(s, "{:02X}", b);
                            if matches!(k, 3 | 5 | 7 | 9) { let _ = write!(s, "-"); }
                        }
                    }
                }
                0x01 => { let _ = write!(s, "LinkAck"); }
                0x02 => {
                    let reason = match f.get(6) {
                        Some(0x00) => "success",
                        Some(0x01) => "timeout",
                        Some(0x02) => "fail",
                        _ => "?",
                    };
                    let _ = write!(s, "LinkClose reason={}", reason);
                }
                op => { let _ = write!(s, "BearerControl opcode=0x{:02X}", op); }
            }
        }
    }
    emit(s);
}
