//! Midea fan (type `FA`) status decode, cross-checked against the
//! manufacturer's Lua `T_0000_FA_*.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `FA` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub gear: u8,
    pub voice: u8,
    pub lock: u8,
    pub power: u8,
    pub swing: u8,
    pub mode: u8,
    pub swing_direction: u8,
    pub swing_angle: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 9;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        gear: b[5],
        voice: b[2],
        lock: b[3],
        power: b[4] & 0x01,
        swing: b[8] & 0x01,
        mode: (b[4] >> 1) & 0x07,
        swing_direction: (b[8] >> 1) & 0x07,
        swing_angle: (b[8] >> 4) & 0x07,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "fan status");
    let _ = write!(w, " gear={}", st.gear);
    let _ = write!(w, " voice={}", st.voice);
    let _ = write!(w, " lock={}", st.lock);
    let _ = write!(w, " power={}", st.power);
    let _ = write!(w, " swing={}", st.swing);
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " swing_direction={}", st.swing_direction);
    let _ = write!(w, " swing_angle={}", st.swing_angle);
    true
}
