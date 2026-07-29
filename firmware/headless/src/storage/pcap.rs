//! PCAP framing for BLE Link-Layer captures.
//!
//! Uses `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` (256): each packet is a 10-byte BLE
//! pseudo-header carrying the RF channel, signal strength, reference access
//! address and status flags, followed by the LL packet itself (access address +
//! PDU). The on-air CRC is not stored — it is only reflected in the flags. This
//! is the classic-`pcap` (not `pcapng`) format nRF/Wireshark round-trip cleanly.
//!
//! Timestamps are firmware uptime (no RTT/RTC), so `ts_sec`/`ts_usec` count from
//! boot; the host tool stamps wall-clock from the capture-file mtime if needed.

/// `libpcap` datalink type for BLE LL with the pseudo-header.
pub const LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR: u32 = 256;
/// Largest record body we cap at: 10 (PHDR) + 4 (AA) + 251 (max PDU) = 265.
pub const SNAPLEN: u32 = 265;

/// PHDR flag bits (subset we can assert). The radio hands us dewhitened bytes and
/// a computed CRC result; we always know the reference AA and channel.
const F_DEWHITENED: u16 = 0x0001;
const F_SIGPOWER_VALID: u16 = 0x0002;
const F_REFAA_VALID: u16 = 0x0010;
const F_CRC_CHECKED: u16 = 0x0400;
const F_CRC_VALID: u16 = 0x0800;

/// The 24-byte classic-pcap global header, written once at the start of each run.
pub fn global_header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xA1B2_C3D4u32.to_le_bytes()); // magic, µs resolution
    h[4..6].copy_from_slice(&2u16.to_le_bytes()); // version major
    h[6..8].copy_from_slice(&4u16.to_le_bytes()); // version minor
    // thiszone (i32) and sigfigs (u32) stay zero.
    h[16..20].copy_from_slice(&SNAPLEN.to_le_bytes());
    h[20..24].copy_from_slice(&LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR.to_le_bytes());
    h
}

/// Maximum bytes one [`record`] can emit: 16 (rec hdr) + 10 (PHDR) + 4 (AA) + PDU.
pub const MAX_RECORD: usize = 16 + 10 + 4 + 258;

/// Build one pcap record for a captured PDU into `out`, returning its length.
///
/// `pdu` is the on-air PDU exactly as the radio delivered it (header + length +
/// payload; the preamble and access address are stripped by hardware, and the AA
/// is re-inserted here as the start of the LL packet). `aa` is the access address
/// in effect: the advertising AA for sniff, or the connection AA for a follow.
pub fn record(
    out: &mut [u8],
    ts_us: u64,
    ch: u8,
    rssi_dbm: i8,
    crc_ok: bool,
    aa: u32,
    pdu: &[u8],
) -> usize {
    let body_len = 10 + 4 + pdu.len(); // PHDR + AA + PDU
    let mut flags = F_DEWHITENED | F_SIGPOWER_VALID | F_REFAA_VALID | F_CRC_CHECKED;
    if crc_ok {
        flags |= F_CRC_VALID;
    }
    let ts_sec = (ts_us / 1_000_000) as u32;
    let ts_usec = (ts_us % 1_000_000) as u32;

    // Record header.
    out[0..4].copy_from_slice(&ts_sec.to_le_bytes());
    out[4..8].copy_from_slice(&ts_usec.to_le_bytes());
    out[8..12].copy_from_slice(&(body_len as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(body_len as u32).to_le_bytes());
    let mut i = 16;

    // BLE LL pseudo-header (10 bytes).
    out[i] = ch;
    out[i + 1] = rssi_dbm as u8;
    out[i + 2] = 0; // noise power (unknown)
    out[i + 3] = 0; // access-address offenses (unknown)
    out[i + 4..i + 8].copy_from_slice(&aa.to_le_bytes()); // reference AA
    out[i + 8..i + 10].copy_from_slice(&flags.to_le_bytes());
    i += 10;

    // LL packet: access address then PDU.
    out[i..i + 4].copy_from_slice(&aa.to_le_bytes());
    i += 4;
    out[i..i + pdu.len()].copy_from_slice(pdu);
    i += pdu.len();
    i
}
