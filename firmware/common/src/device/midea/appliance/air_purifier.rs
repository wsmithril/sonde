//! Midea (type `FC`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_FC_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `FC` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub pm25_low: u8,
    pub tvoc: u8,
    pub error_code: u8,
    pub power: u8,
    pub mode: u8,
    pub fan_speed: u8,
    pub step_mintues: u8,
    pub humidify_mode: u8,
    pub anion: u8,
    pub ash_tvoc: u8,
    pub hour: u8,
}

/// Status-body minimum length (the highest byte the decoder reads).
const S_MIN_LEN: usize = 22;

/// Parse the status body per the Lua's byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        pm25_low: b[13],
        tvoc: b[15],
        error_code: b[21],
        power: b[1] & 0x01,
        mode: b[2] & 0xF0,
        fan_speed: b[3] & 0x7F,
        step_mintues: b[5] & 0x03,
        humidify_mode: b[8] & 0x70,
        anion: b[9] & 0x40,
        ash_tvoc: b[12] & 0x07,
        hour: (b[5] >> 2) & 0x1F,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "FC status");
    let _ = write!(w, " pm25_low={}", st.pm25_low);
    let _ = write!(w, " tvoc={}", st.tvoc);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " power={}", st.power);
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " fan_speed={}", st.fan_speed);
    let _ = write!(w, " step_mintues={}", st.step_mintues);
    let _ = write!(w, " humidify_mode={}", st.humidify_mode);
    let _ = write!(w, " anion={}", st.anion);
    let _ = write!(w, " ash_tvoc={}", st.ash_tvoc);
    let _ = write!(w, " hour={}", st.hour);
    true
}
