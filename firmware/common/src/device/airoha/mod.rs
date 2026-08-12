//! Airoha "RACE" command protocol over BLE GATT — the BLE half of the blue-tap
//! assessment (CVE-2025-20700/-20701/-20702: missing authentication on the RACE
//! GATT transport of Airoha-SoC TWS earbuds). Many earbud brands on Airoha AB15xx
//! SoCs answer RACE commands from any connected central, with no pairing/challenge.
//!
//! Transport: a service with a write characteristic (TX, central→device) and a
//! notify characteristic (RX, device→central). Two UUID families are seen:
//!   * Sony variant — service DC405470-A351-4A59-97D8-2E2E3B207FBB, TX
//!     BFD869FA-…, RX 2A6B6575-… (captured on a WF-1000XM5).
//!   * Standard Airoha — characteristic UUIDs whose bytes spell "…Airoha BLE"
//!     (43484152-2DAB-XX41-6972-6F6861424C45); XX = '2' (0x32) TX, '1' (0x31) RX.
//!
//! Frame (from auracast-research/race-toolkit `librace`):
//! ```text
//!   [head=0x05][type][length: u16 LE][cmd_id: u16 LE][payload…]
//! ```
//! `length` counts the cmd_id plus payload (so 2 for an empty-payload command).
//! `type`: 0x5A command-with-response, 0x5C command-no-response, 0x5B response,
//! 0x5D indication. Confirmed example: READ_SDK_VERSION (cmd 0x0301) = the bytes
//! `05 5A 02 00 01 03`.
//!
//! HARDWARE-UNVERIFIED beyond the framing and the READ_SDK_VERSION probe: the
//! other cmd_ids are from the reference opcode list but their request/response
//! bytes are built here from the confirmed framing, not observed on air.
#![allow(dead_code)]

use heapless::Vec;

/// RACE frame header bytes.
pub const HEAD: u8 = 0x05;
pub const TYPE_CMD_RSP: u8 = 0x5A; // command, response expected
pub const TYPE_CMD_NORSP: u8 = 0x5C; // command, no response
pub const TYPE_RSP: u8 = 0x5B; // response to a command
pub const TYPE_IND: u8 = 0x5D; // unsolicited indication

/// Command ids (reference opcode list; only READ_SDK_VERSION is byte-confirmed).
pub const CMD_READ_SDK_VERSION: u16 = 0x0301;
pub const CMD_GET_BD_ADDRESS: u16 = 0x0CD5;

/// Max RACE frame we build (header 6 + small payload).
pub type Frame = Vec<u8, 32>;

/// A discovered RACE transport: the TX (write) and RX (notify) value handles.
#[derive(Clone, Copy)]
pub struct Profile {
    pub tx_h: u16,
    pub rx_h: u16,
}

/// Role of a characteristic within the RACE profile.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Tx,
    Rx,
}

// ── UUIDs (on-air little-endian, for matching a discovered UUID) ───────────────

/// Sony-variant RACE service DC405470-A351-4A59-97D8-2E2E3B207FBB.
pub const SVC_SONY_LE: [u8; 16] = [
    0xBB, 0x7F, 0x20, 0x3B, 0x2E, 0x2E, 0xD8, 0x97, 0x59, 0x4A, 0x51, 0xA3, 0x70, 0x54, 0x40, 0xDC,
];
/// Sony-variant TX (write) BFD869FA-A3F2-4C2F-BCFF-3EB1EC80CEAD.
const TX_SONY_LE: [u8; 16] = [
    0xAD, 0xCE, 0x80, 0xEC, 0xB1, 0x3E, 0xFF, 0xBC, 0x2F, 0x4C, 0xF2, 0xA3, 0xFA, 0x69, 0xD8, 0xBF,
];
/// Sony-variant RX (notify) 2A6B6575-FAF6-418C-923F-CCD63A56D955.
const RX_SONY_LE: [u8; 16] = [
    0x55, 0xD9, 0x56, 0x3A, 0xD6, 0xCC, 0x3F, 0x92, 0x8C, 0x41, 0xF6, 0xFA, 0x75, 0x65, 0x6B, 0x2A,
];

/// `true` if a discovered service UUID (on-air LE) is a known RACE service.
pub fn is_race_service(uuid_le: &[u8]) -> bool {
    uuid_le.len() == 16 && uuid_le == SVC_SONY_LE
}

/// `true` if a characteristic UUID (on-air LE) is a standard Airoha char — its
/// big-endian bytes [7..16] spell "Airoha BLE". Recognises the family on non-Sony
/// earbuds even when the service UUID is the standard "PRIM" base.
pub fn is_airoha_char(uuid_le: &[u8]) -> bool {
    // BE[7..16] == LE[8..0 reversed]; check the on-air LE tail directly:
    // LE bytes [0..9] are BE bytes [15..7] reversed = "ELB ahoriA".
    const MARKER_LE: [u8; 9] = [0x45, 0x4C, 0x42, 0x61, 0x68, 0x6F, 0x72, 0x69, 0x41]; // "ELBahoriA"
    uuid_le.len() == 16 && uuid_le[0..9] == MARKER_LE
}

/// Classify a RACE characteristic UUID (on-air LE) as TX or RX. Recognises the
/// Sony-variant exact UUIDs and the standard Airoha '2'/'1' marker chars. Returns
/// `None` for anything else (the caller can still fall back to write/notify props).
pub fn role(uuid_le: &[u8]) -> Option<Role> {
    if uuid_le.len() != 16 {
        return None;
    }
    if uuid_le == TX_SONY_LE {
        return Some(Role::Tx);
    }
    if uuid_le == RX_SONY_LE {
        return Some(Role::Rx);
    }
    // Standard Airoha: BE byte [6] is the ASCII role digit; on-air LE that is [9].
    if is_airoha_char(uuid_le) {
        return match uuid_le[9] {
            0x32 => Some(Role::Tx), // '2'
            0x31 => Some(Role::Rx), // '1'
            _ => None,
        };
    }
    None
}

// ── Frame build / parse ───────────────────────────────────────────────────────

/// Build a RACE command frame: `[0x05][type][len u16 LE][cmd_id u16 LE][payload]`,
/// where `len` counts cmd_id + payload. `None` if it would exceed the buffer.
pub fn build_cmd(cmd_id: u16, payload: &[u8], response: bool) -> Option<Frame> {
    let mut f = Frame::new();
    let len = (2 + payload.len()) as u16;
    f.push(HEAD).ok()?;
    f.push(if response { TYPE_CMD_RSP } else { TYPE_CMD_NORSP }).ok()?;
    f.extend_from_slice(&len.to_le_bytes()).ok()?;
    f.extend_from_slice(&cmd_id.to_le_bytes()).ok()?;
    f.extend_from_slice(payload).ok()?;
    Some(f)
}

/// The confirmed READ_SDK_VERSION probe (`05 5A 02 00 01 03`) — an unauthenticated
/// info-disclosure command used to test whether the RACE channel answers at all.
pub fn read_sdk_version() -> Frame {
    // Unwrap-free: the fixed 6-byte frame always fits.
    build_cmd(CMD_READ_SDK_VERSION, &[], true).unwrap_or_default()
}

/// Parse a RACE reply. Returns `(cmd_id, payload)` when `v` is a well-formed
/// response or indication frame; `None` otherwise.
pub fn parse_reply(v: &[u8]) -> Option<(u16, &[u8])> {
    if v.len() < 6 || v[0] != HEAD || !matches!(v[1], TYPE_RSP | TYPE_IND) {
        return None;
    }
    let len = u16::from_le_bytes([v[2], v[3]]) as usize; // cmd_id + payload
    if len < 2 || 4 + len > v.len() {
        return None;
    }
    let cmd_id = u16::from_le_bytes([v[4], v[5]]);
    Some((cmd_id, &v[6..4 + len]))
}
