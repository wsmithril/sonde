//! Daikin Madoka control-channel framing + command/TLV decode.
//!
//! ## Transport (chunk framing)
//! The MTU is 20 bytes, so a message fragments across chunks. Byte 0 of every
//! chunk is its index (`0x00`, `0x01`, …); chunk 0 additionally carries a
//! total-length byte at offset 1 that **counts itself**, so the reassembled
//! payload is `total_len - 1` bytes:
//!
//! ```text
//! chunk 0:  00 <total_len> <data…>        (data starts at offset 2)
//! chunk N:  NN <data…>                    (data starts at offset 1)
//! ```
//!
//! ## Payload (command + TLV)
//! The reassembled payload is a command ID followed by TLV items
//! `[id:1][size:1][value:size]`. Getters are `00xx`/`03xx`, their setters
//! `40xx`/`43xx`. A request with no arguments carries the empty item `00 00`.
//!
//! The reversed docs are ambiguous on whether the command ID is 2 or 3 bytes;
//! every documented code fits two bytes and the getter/setter pairs are 2-byte,
//! so this decodes a 2-byte command and walks TLVs after it. Field IDs are
//! command-specific (`0x20` means on/off in one command, mode in another), so
//! values are shown generically with a few unambiguous fields interpreted.
//!
//! Since Daikin frames carry no magic byte or checksum, [`frame`] is deliberately
//! strict — it emits only when the chunk-0 length is self-consistent, the command
//! ID is one it knows, and the TLVs walk cleanly to the declared end. That makes
//! a false decode on an unrelated characteristic value very unlikely.

use core::fmt::Write;

use crate::decoder::protocol::{line, send};

/// Command ID (big-endian, as written in the reversed docs) → name.
fn command_name(cmd: u16) -> Option<&'static str> {
    Some(match cmd {
        0x0000 => "GetGeneralInfo",
        0x0020 => "GetSettingStatus",
        0x4020 => "SetSettingStatus",
        0x0030 => "GetOperationMode",
        0x4030 => "SetOperationMode",
        0x0040 => "GetSetpoint",
        0x4040 => "SetSetpoint",
        0x0050 => "GetFanSpeed",
        0x4050 => "SetFanSpeed",
        0x4220 => "DisableCleanFilterIndicator",
        0x0110 => "GetSensorInformation",
        0x0130 => "GetMaintenanceInformation",
        0x0302 => "GetEyeBrightness",
        0x4302 => "SetEyeBrightness",
        _ => return None,
    })
}

/// The 5 operation-mode codes shared by Get/SetOperationMode (field 0x20).
fn mode_name(v: u8) -> &'static str {
    match v {
        0 => "fan",
        1 => "dry",
        2 => "auto",
        3 => "cool",
        4 => "heat",
        5 => "ventilation",
        _ => "?",
    }
}

/// Decode a captured characteristic value that may be a Daikin Madoka frame.
///
/// Only single-chunk frames are decoded (chunk 0 whose declared length fits the
/// value); a multi-chunk message would need reassembly state the stateless decode
/// path does not carry, so its continuation chunks are left to the raw hex dump.
/// A no-op on anything that is not a well-formed, known Daikin command.
pub fn frame(v: &[u8]) {
    // Chunk 0 header: [00][total_len]. total_len counts itself, so payload is
    // total_len-1 bytes at offset 2.
    if v.len() < 4 || v[0] != 0x00 {
        return;
    }
    let total_len = v[1] as usize;
    if total_len < 3 {
        return; // need at least the length byte + a 2-byte command
    }
    let payload_len = total_len - 1; // bytes after the length byte
    let end = 2 + payload_len;
    if end > v.len() {
        return; // continuation chunk(s) not present — cannot decode here
    }
    let payload = &v[2..end];

    let cmd = u16::from_be_bytes([payload[0], payload[1]]);
    let Some(name) = command_name(cmd) else {
        return; // unknown command → not (recognisably) a Daikin frame
    };

    // Walk the TLV items after the command, bailing if any runs past the end —
    // that inconsistency means this was not really a Daikin frame.
    let mut items: heapless::Vec<(u8, &[u8]), 12> = heapless::Vec::new();
    let mut i = 2;
    while i + 2 <= payload.len() {
        let id = payload[i];
        let size = payload[i + 1] as usize;
        // The empty item 00 00 is the no-argument / terminator marker.
        if id == 0x00 && size == 0x00 {
            i += 2;
            continue;
        }
        let vstart = i + 2;
        let vend = vstart + size;
        if vend > payload.len() {
            return; // declared field overruns the payload → not a valid frame
        }
        if items.push((id, &payload[vstart..vend])).is_err() {
            break;
        }
        i = vend;
    }

    let mut s = line();
    let _ = write!(s, "  Daikin {} (0x{:04X})", name, cmd);
    for (id, val) in &items {
        let _ = write!(s, " [{:02X}=", id);
        interpret(&mut s, cmd, *id, val);
        let _ = write!(s, "]");
    }
    send(s);
}

/// Append the value for one TLV field, decoding the few command/field pairs whose
/// meaning is unambiguous (on/off, mode, fan speed, integer sensor temperature)
/// and showing the rest as hex — setpoints are a 2-byte GFLOAT that is easy to
/// render wrong, so those stay raw.
fn interpret(s: &mut crate::LogLine, cmd: u16, id: u8, val: &[u8]) {
    match (cmd, id) {
        // on/off status
        (0x0020 | 0x4020, 0x20) if val.len() == 1 => {
            let _ = write!(s, "{}", if val[0] != 0 { "on" } else { "off" });
        }
        // operation mode
        (0x0030 | 0x4030, 0x20) if val.len() == 1 => {
            let _ = write!(s, "{}", mode_name(val[0]));
        }
        // fan speed (5=max, 2-4=medium, 1=low), for cooling(0x20)/heating(0x21)
        (0x0050 | 0x4050, 0x20 | 0x21) if val.len() == 1 => {
            let f = match val[0] {
                5 => "max",
                2..=4 => "medium",
                1 => "low",
                _ => "?",
            };
            let _ = write!(s, "{}({})", f, val[0]);
        }
        // sensor: indoor temperature is a 1-byte °C; outdoor is 2B (0xFF = n/a)
        (0x0110, 0x40) if val.len() == 1 => {
            let _ = write!(s, "{}C", val[0] as i8);
        }
        _ => {
            for &b in val {
                let _ = write!(s, "{:02X}", b);
            }
        }
    }
}
