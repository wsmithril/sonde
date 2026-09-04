//! Midea fan-and-light — a separate BLE family from the 0x06A8 appliance
//! control channel. Exposes a `0xAAAA` GATT service (`0xBBB0` control write,
//! `0xBBB1` state notify) and broadcasts its full state in the `0x06A8`
//! advertisement under a `81 63 01` payload header, so state is readable
//! passively without connecting. State and control frames are obfuscated with a
//! per-device 16-byte XOR base derived from the MAC address. Format and XOR
//! bases per the public selfdcl/midea_fan_light_ble integration.

use core::fmt::Write;

/// GATT service UUID of the fan-light control channel.
pub const SERVICE_UUID: u16 = 0xAAAA;
/// Control write characteristic.
pub const CONTROL_UUID: u16 = 0xBBB0;
/// State notify characteristic.
pub const STATE_UUID: u16 = 0xBBB1;

/// The `0x06A8` payload header that marks a fan-light state advertisement.
const STATE_AD_HEADER: [u8; 3] = [0x81, 0x63, 0x01];

/// The 16-byte XOR base used when the device MAC has no captured base.
const DEFAULT_XOR_BASE: [u8; 16] = [
    0xD1, 0xF3, 0x51, 0xD3, 0x73, 0x95, 0xF3, 0x60, 0x82, 0xE0, 0x22, 0x80, 0xA2, 0x46, 0x44, 0x31,
];

/// XOR bases captured from specific fan-lights, keyed by MAC address.
const KNOWN_XOR_BASES: [(&[u8; 6], [u8; 16]); 3] = [
    (
        &[0x80, 0x22, 0x00, 0x40, 0x83, 0x19],
        [
            0x19, 0x3B, 0x99, 0xC3, 0x83, 0xA5, 0x03, 0x40, 0x62, 0xC0, 0x22, 0x80, 0xA2, 0x7E,
            0x9C, 0x59,
        ],
    ),
    (
        &[0x80, 0x22, 0x00, 0x91, 0x78, 0x26],
        [
            0x26, 0x48, 0xA6, 0x09, 0x78, 0x9A, 0xF8, 0x91, 0xB3, 0x11, 0x22, 0x80, 0xA2, 0xD1,
            0x9E, 0xB7,
        ],
    ),
    (
        &[0x80, 0x22, 0x00, 0xA0, 0x2F, 0xDA],
        [
            0xDA, 0xFC, 0x5A, 0xCF, 0x2F, 0x51, 0xAF, 0xA0, 0xC2, 0x20, 0x22, 0x80, 0xA2, 0x4B,
            0x09, 0x7A,
        ],
    ),
];

/// A decoded fan-light state, from the advertisement or a BBB1 notification.
#[derive(Clone, Copy)]
pub struct State {
    /// Bit flags: 0x01 light, 0x02 fan, 0x04 night-light, 0x20 reverse.
    pub mode: u8,
    /// Light brightness, 0..255.
    pub brightness: u8,
    /// Color temperature, 0..255 (→ 2700..6500 K).
    pub color: u8,
    /// Remaining countdown, minutes.
    pub timer_minutes: u16,
    /// One-based fan speed, 0 when off.
    pub speed: u8,
}

/// Extract the flat 6-byte state (`mode, brightness, color, timer LE, speed`)
/// from a fan-light `0x06A8` state advertisement, if present. Also the
/// advert-classification entry point. The state payload sits at fixed offsets
/// after the `81 63 01` header + embedded MAC.
pub fn state_of_ad(ad: &[u8]) -> Option<[u8; 6]> {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        let atype = ad[i + 1];
        let data = &ad[i + 2..i + 1 + flen];
        // mfg data: [A8 06][81 63 01][mac 6][state 11]; payload = data[2..].
        if atype == 0xFF
            && data.len() >= 22
            && data[0] == 0xA8
            && data[1] == 0x06
            && data[2..5] == STATE_AD_HEADER
        {
            return Some([
                data[2 + 11], // mode
                data[2 + 14], // brightness
                data[2 + 15], // color
                data[2 + 16], // timer lo
                data[2 + 17], // timer hi
                data[2 + 18], // speed
            ]);
        }
        i += 1 + flen;
    }
    None
}

/// The 16-byte XOR base for a device MAC (captured base first, default fallback).
pub fn xor_base(mac: &[u8; 6]) -> [u8; 16] {
    for (known, base) in KNOWN_XOR_BASES {
        if known == mac {
            return base;
        }
    }
    DEFAULT_XOR_BASE
}

/// Decode a 13-byte BBB1 state notification with the device's XOR base. The
/// frame is `[0x0C][seq<<4|0x0B] ‖ XOR(plaintext 11)`; the plaintext opens
/// `08 00` and carries the same fields as the advertisement.
pub fn decode_state_notify(notif: &[u8], base: &[u8; 16]) -> Option<State> {
    if notif.len() != 13 || notif[0] != 0x0C {
        return None;
    }
    let seq = ((notif[1] >> 4) & 0x0F) as usize;
    let mut plain = [0u8; 11];
    for i in 0..11 {
        plain[i] = notif[2 + i] ^ base[(seq + 14 + i) & 0x0F];
    }
    if plain[..2] != [0x08, 0x00] {
        return None;
    }
    Some(State {
        mode: plain[2],
        brightness: plain[5],
        color: plain[6],
        timer_minutes: u16::from_le_bytes([plain[7], plain[8]]),
        speed: plain[9],
    })
}

/// Build an 18-byte BBB0 control write: `[0x10][seq<<4|0x0B] ‖ XOR(plaintext)`
/// where the plaintext is `01 01 00 cmd 0… checksum`. Kept for a future control
/// feature — the recon probe never sends commands.
#[allow(dead_code)]
pub fn build_control_frame(command: u8, seq: u8, base: &[u8; 16]) -> [u8; 18] {
    let mut plain = [0u8; 16];
    plain[0] = 0x01;
    plain[1] = 0x01;
    plain[3] = command;
    plain[15] = plain[..15].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    let mut out = [0u8; 18];
    out[0] = 0x10;
    out[1] = (seq << 4) | 0x0B;
    let s = seq as usize;
    for i in 0..16 {
        out[2 + i] = plain[i] ^ base[(s + 14 + i) & 0x0F];
    }
    out
}

/// Format a decoded state for the log line.
pub fn fmt_state(st: &State) -> heapless::String<80> {
    let mut s = heapless::String::new();
    let _ = write!(
        s,
        "mode=0x{:02X} bri={} cct={} timer={}min speed={}",
        st.mode, st.brightness, st.color, st.timer_minutes, st.speed
    );
    s
}
