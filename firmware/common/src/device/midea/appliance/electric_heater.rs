//! Midea electric heater (type `FB`) status decode, cross-checked against the
//! manufacturer's Lua `T_0000_FB_3.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`).

use crate::device::midea::status;

/// Decoded `FB` electric-heater status.
#[derive(Clone, Copy)]
pub struct Status {
    pub power_value: u8,
    pub mode_value: u8,
    pub gear_value: u8,
    pub temperature_value: u8,
    pub humidity_value: u8,
    pub cur_humidity_value: u8,
    pub cur_temperature_value: u8,
    pub lock_value: u8,
    pub humidity_mode_value: u8,
}

const S_MIN_LEN: usize = 19;

/// Parse the status body per the Lua's `binToModel`.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        power_value: b[0],
        mode_value: b[4],
        gear_value: b[5],
        temperature_value: b[6],
        humidity_value: b[7],
        cur_humidity_value: b[12],
        cur_temperature_value: b[13],
        lock_value: b[18],
        humidity_mode_value: b[9] & 0xF0,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "electric-heater status");
    let _ = write!(w, " power_value={}", st.power_value);
    let _ = write!(w, " mode_value={}", st.mode_value);
    let _ = write!(w, " gear_value={}", st.gear_value);
    let _ = write!(w, " temperature_value={}", st.temperature_value);
    let _ = write!(w, " humidity_value={}", st.humidity_value);
    let _ = write!(w, " cur_humidity_value={}", st.cur_humidity_value);
    let _ = write!(w, " cur_temperature_value={}", st.cur_temperature_value);
    let _ = write!(w, " lock_value={}", st.lock_value);
    let _ = write!(w, " humidity_mode_value={}", st.humidity_mode_value);
    true
}
