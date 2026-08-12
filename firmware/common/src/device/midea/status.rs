//! Per-device-type status decode for the M-Smart fleet.
//!
//! Byte offsets are ported from `rokam/midea-local` (`midealocal/devices/<type>/
//! message.py`), calibrated against sonde's working AC codec
//! ([`super::control::parse_status_frame`]): the reference library's `body[N]`
//! equals the decrypted appliance frame's `t[10 + N]`, where `t[10]` is the
//! body-type byte (0xC0 AC, 0xC8/0xA0 FC/FD, 0x01/0x02 CE/E2, …). Within a device
//! type the body-type byte selects the query (`C8`) vs notify (`A0`) layout where
//! they differ.
//!
//! Only unambiguous fields are decoded to values — booleans, integer sensors
//! (PM2.5, CO₂, humidity, temperature, filter life), with the exact scaling from
//! the source. Enum fields whose integer→label map is not carried here are shown
//! as their raw masked value rather than guessed. Every byte access is bounds- and
//! `0xFF`-guarded (0xFF = "sensor unavailable"), matching the reference guards.
//!
//! HARDWARE-UNVERIFIED for every non-AC type: there are no captured status frames
//! for these appliances to test against, so the offsets are trusted from the
//! reference lib, not confirmed on air. AC stays in [`super::control`].

use core::fmt::Write;

use crate::decoder::LogStr;

/// Validate the decrypted appliance frame (`0xAA`, length, checksum) and return
/// the body slice `t[10..]`. Mirrors [`super::control::parse_status_frame`]'s
/// framing checks so both agree on what a sound frame is.
fn frame_body(t: &[u8]) -> Option<&[u8]> {
    if t.len() < 12 || t[0] != 0xAA {
        return None;
    }
    let n = t[1] as usize;
    if 1 + n > t.len() {
        return None;
    }
    // Checksum: wrapping-sub fold over t[1..1+n] is zero on a good frame.
    if t[1..1 + n].iter().fold(0u8, |a, &x| a.wrapping_sub(x)) != 0 {
        return None;
    }
    Some(&t[10..])
}

/// Decode a device's status frame into `s`, keyed on the SN device-type code
/// (`sn[8..10]`). Returns `true` if a codec recognised the frame and wrote
/// fields. The caller logs the raw bytes regardless, so an unrecognised type or
/// body layout simply falls back to that hex.
pub fn decode(type_code: &[u8], t: &[u8], s: &mut LogStr) -> bool {
    let Some(b) = frame_body(t) else { return false };
    match type_code {
        b"FC" => fc(b, s),
        b"A1" => a1(b, s),
        b"FD" => fd(b, s),
        b"CE" => ce(b, s),
        b"E2" => e2(b, s),
        _ => false,
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn get(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).copied()
}
/// A little-endian 16-bit sensor at `lo,hi`, with 0xFF high byte meaning
/// "unavailable" (returns `None`), matching the reference guards.
fn u16le(b: &[u8], lo: usize, hi: usize) -> Option<u16> {
    let l = get(b, lo)?;
    let h = get(b, hi)?;
    if h == 0xFF {
        return None;
    }
    Some(l as u16 | ((h as u16) << 8))
}
/// A big-endian 16-bit sensor at `hi,lo` (CE's convention), 0xFF high = unavailable.
fn u16be(b: &[u8], hi: usize, lo: usize) -> Option<u16> {
    let h = get(b, hi)?;
    let l = get(b, lo)?;
    if h == 0xFF {
        return None;
    }
    Some(((h as u16) << 8) | l as u16)
}
fn onoff(s: &mut LogStr, name: &str, on: bool) {
    let _ = write!(s, " {}={}", name, if on { "on" } else { "off" });
}
/// Write a value scaled by 1/10 as `int.frac` (used for /10 sensors).
fn tenths(s: &mut LogStr, name: &str, v: i32, unit: &str) {
    let a = v.abs();
    let _ = write!(s, " {}={}{}.{}{}", name, if v < 0 { "-" } else { "" }, a / 10, a % 10, unit);
}

// ── FC air-purifier ──────────────────────────────────────────────────────────
// body[0]: 0xC8 general / 0xA0 notify. Sensors share offsets; anion/child_lock
// and hcho move between the two. Enums (mode/fan/screen) shown raw.
fn fc(b: &[u8], s: &mut LogStr) -> bool {
    let btype = match get(b, 0) {
        Some(t) => t,
        None => return false,
    };
    let notify = btype == 0xA0;
    onoff(s, "power", get(b, 1).unwrap_or(0) & 0x01 != 0);
    if let Some(m) = get(b, 2) {
        let _ = write!(s, " mode=0x{:02X}", m & 0xF0);
    }
    if let Some(f) = get(b, 3) {
        let _ = write!(s, " fan=0x{:02X}", f & 0x7F);
    }
    if let Some(sd) = get(b, 9) {
        let _ = write!(s, " screen=0x{:02X}", sd & 0x07);
    }
    if let Some(pm) = u16le(b, 13, 14) {
        let _ = write!(s, " pm25={}", pm);
    }
    if let Some(t) = get(b, 15).filter(|&v| v != 0xFF) {
        let _ = write!(s, " tvoc={}", t);
    }
    if notify {
        onoff(s, "anion", get(b, 10).unwrap_or(0) & 0x20 != 0);
        onoff(s, "lock", get(b, 10).unwrap_or(0) & 0x10 != 0);
        if let Some(h) = u16le(b, 30, 31) {
            let _ = write!(s, " hcho={}", h);
        }
    } else {
        onoff(s, "anion", get(b, 19).unwrap_or(0) & 0x40 != 0);
        onoff(s, "lock", get(b, 8).unwrap_or(0) & 0x80 != 0);
        if let Some(f1) = get(b, 23) {
            let _ = write!(s, " filter1={}%", f1);
        }
        if let Some(f2) = get(b, 24) {
            let _ = write!(s, " filter2={}%", f2);
        }
        if let Some(h) = u16le(b, 37, 38) {
            let _ = write!(s, " hcho={}", h);
        }
    }
    true
}

// ── A1 dehumidifier ─────────────────────────────────────────────────────────
fn a1(b: &[u8], s: &mut LogStr) -> bool {
    onoff(s, "power", get(b, 1).unwrap_or(0) & 0x01 != 0);
    if let Some(m) = get(b, 2) {
        let _ = write!(s, " mode=0x{:02X}", m & 0x0F);
    }
    if let Some(f) = get(b, 3) {
        let _ = write!(s, " fan=0x{:02X}", f & 0x7F);
    }
    if let Some(th) = get(b, 7) {
        let _ = write!(s, " tgt_hum={}%", th);
    }
    onoff(s, "lock", get(b, 8).unwrap_or(0) & 0x80 != 0);
    onoff(s, "anion", get(b, 9).unwrap_or(0) & 0x40 != 0);
    onoff(s, "pump", get(b, 9).unwrap_or(0) & 0x08 != 0);
    if let Some(tk) = get(b, 10) {
        let _ = write!(s, " tank={}", tk & 0x7F);
    }
    if let Some(h) = get(b, 16) {
        let _ = write!(s, " hum={}%", h);
    }
    // current_temperature = (body[17] - 50) / 2  → half-degree °C
    if let Some(t) = get(b, 17) {
        tenths(s, "temp", (t as i32 - 50) * 5, "C");
    }
    onoff(s, "swing", get(b, 19).unwrap_or(0) & 0x20 != 0);
    true
}

// ── FD humidifier ───────────────────────────────────────────────────────────
// body[0]: 0xC8 general / 0xA0 notify — `mode` and `disinfect` move.
fn fd(b: &[u8], s: &mut LogStr) -> bool {
    let notify = get(b, 0) == Some(0xA0);
    onoff(s, "power", get(b, 1).unwrap_or(0) & 0x01 != 0);
    if let Some(f) = get(b, 3) {
        let _ = write!(s, " fan=0x{:02X}", f & 0x7F);
    }
    let mode = if notify {
        get(b, 10).map(|v| v & 0x07)
    } else {
        get(b, 8).map(|v| (v & 0x70) >> 4)
    };
    if let Some(m) = mode {
        let _ = write!(s, " mode={}", m);
    }
    if let Some(th) = get(b, 7) {
        let _ = write!(s, " tgt_hum={}%", th);
    }
    if let Some(h) = get(b, 16) {
        let _ = write!(s, " hum={}%", h);
    }
    if let Some(t) = get(b, 17) {
        tenths(s, "temp", (t as i32 - 50) * 5, "C");
    }
    if let Some(tk) = get(b, 10) {
        let _ = write!(s, " tank={}", tk);
    }
    if let Some(sd) = get(b, 9) {
        let _ = write!(s, " screen=0x{:02X}", sd & 0x07);
    }
    true
}

// ── CE fresh-air ────────────────────────────────────────────────────────────
fn ce(b: &[u8], s: &mut LogStr) -> bool {
    onoff(s, "power", get(b, 1).unwrap_or(0) & 0x80 != 0);
    onoff(s, "lock", get(b, 1).unwrap_or(0) & 0x20 != 0);
    if let Some(f) = get(b, 2) {
        let _ = write!(s, " fan={}", f);
    }
    // Big-endian 16-bit sensors here (reference uses (hi<<8)+lo, hi first).
    if let Some(pm) = u16be(b, 3, 4) {
        let _ = write!(s, " pm25={}", pm);
    }
    if let Some(co2) = u16be(b, 5, 6) {
        let _ = write!(s, " co2={}", co2);
    }
    // humidity = ((body[7]<<8)+body[8]) / 10
    if let Some(hum) = u16be(b, 7, 8) {
        tenths(s, "hum", hum as i32, "%");
    }
    onoff(s, "eco", get(b, 17).unwrap_or(0) & 0x04 != 0);
    onoff(s, "sleep", get(b, 17).unwrap_or(0) & 0x02 != 0);
    if let Some(f) = get(b, 18) {
        if f & 0x01 != 0 {
            let _ = write!(s, " filter-clean!");
        }
        if f & 0x02 != 0 {
            let _ = write!(s, " filter-change!");
        }
    }
    true
}

// ── E2 electric water heater ─────────────────────────────────────────────────
fn e2(b: &[u8], s: &mut LogStr) -> bool {
    let flags = get(b, 2).unwrap_or(0);
    onoff(s, "power", flags & 0x01 != 0);
    onoff(s, "heating", flags & 0x04 != 0);
    onoff(s, "keep-warm", flags & 0x08 != 0);
    if let Some(t) = get(b, 4) {
        let _ = write!(s, " temp={}C", t);
    }
    if let Some(t) = get(b, 11) {
        let _ = write!(s, " tgt={}C", t);
    }
    if let Some(p) = get(b, 22) {
        onoff(s, "protect", p & 0x02 != 0);
    }
    if let Some(hp) = get(b, 34) {
        let _ = write!(s, " heat_pwr={}W", hp as u32 * 100);
    }
    true
}
