//! Midea dehumidifier (type `A1`) status decode, cross-checked against the
//! manufacturer's Lua `T_0000_A1_*.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `A1` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub wind_speed: u8,
    pub humidity: u8,
    pub cur_humidity: u8,
    pub tank_status: u8,
    pub power: u8,
    pub mode: u8,
    pub anion: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 17;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        wind_speed: b[3],
        humidity: b[7],
        cur_humidity: b[16],
        tank_status: b[10],
        power: b[1] & 0x01,
        mode: b[2] & 0x0F,
        anion: b[9] & 0x40,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "dehumidifier status");
    let _ = write!(w, " wind_speed={}", st.wind_speed);
    let _ = write!(w, " humidity={}", st.humidity);
    let _ = write!(w, " cur_humidity={}", st.cur_humidity);
    let _ = write!(w, " tank_status={}", st.tank_status);
    let _ = write!(w, " power={}", st.power);
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " anion={}", st.anion);
    true
}
