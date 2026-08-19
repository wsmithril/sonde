//! Google "uWeave" (BLE Weave) transport-header decode.
//!
//! uWeave is the framed message transport carried by service 0xFEF3 (Nearby
//! Connections / Quick Share) and by CryptAuth "Better Together". A notification on
//! the RX characteristic (`…001A11000102`) is a uWeave packet whose first byte is a
//! header. The framing below is from Chromium's BSD-licensed source
//! (`ble_weave_defines.h`, `ble_weave_packet_generator.cc`) — a decode, not a guess:
//!
//! * bit 7 (0x80): packet type — 1 = CONTROL, 0 = DATA
//! * bits 6–4 (0x70): packet counter (0..7)
//! * CONTROL low nibble (0x0F): command — 0 REQUEST, 1 RESPONSE, 2 CLOSE
//! * DATA bit 3 (0x08): first fragment; bit 2 (0x04): last fragment
//!
//! So e.g. `0x82` = CONTROL, counter 0, command 2 = CONNECTION_CLOSE.
//!
//! [`describe`] decodes a uWeave notification value into a log line; the
//! connection code has not adopted it yet, so it is kept available for the
//! value-read/decode path.
#![allow(dead_code)]

use core::fmt::Write;

use crate::decoder::LogStr;

/// True if `uuid_le` (on-air little-endian) is one of the Google uWeave
/// characteristics — identified by the shared tail `00 1A 11 00 01` (big-endian),
/// which is the same across the `…0000-…` and `…0004-…` field spellings.
fn is_uweave(uuid_le: &[u8]) -> bool {
    // Big-endian bytes [10..15] are on-air little-endian bytes [5..0].
    uuid_le.len() == 16
        && uuid_le[5] == 0x00
        && uuid_le[4] == 0x1A
        && uuid_le[3] == 0x11
        && uuid_le[2] == 0x00
        && uuid_le[1] == 0x01
}

/// If `uuid_le` is a uWeave characteristic and `v` is non-empty, append a decode of
/// its 1-byte header to `s` and return `Some(1)` (the bytes consumed — the header
/// only; any framed payload after it is the caller's to hexdump). `None` when this
/// is not a uWeave characteristic, so the caller falls back to its generic decode.
pub(crate) fn describe(uuid_le: &[u8], v: &[u8], s: &mut LogStr) -> Option<usize> {
    if !is_uweave(uuid_le) || v.is_empty() {
        return None;
    }
    let b = v[0];
    let counter = (b >> 4) & 0x07;
    if b & 0x80 != 0 {
        let cmd = match b & 0x0F {
            0 => "CONNECTION_REQUEST",
            1 => "CONNECTION_RESPONSE",
            2 => "CONNECTION_CLOSE",
            other => {
                let _ = write!(s, "        uWeave CONTROL cmd=0x{:X} (counter {})", other, counter);
                return Some(1);
            }
        };
        let _ = write!(s, "        uWeave CONTROL {} (counter {})", cmd, counter);
    } else {
        let first = if b & 0x08 != 0 { " first" } else { "" };
        let last = if b & 0x04 != 0 { " last" } else { "" };
        let _ = write!(s, "        uWeave DATA (counter {}{}{})", counter, first, last);
    }
    Some(1)
}
