//! Midea mb4 (type `B4`) status decode, cross-checked against the
//! manufacturer's Lua `T_0000_B4_*.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `B4` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub work_status: u8,
    pub work_hour: u8,
    pub work_minute: u8,
    pub work_mode: u8,
    pub temperature: u8,
    pub underside_tube_temp: u8,
    pub cur_temperature_above: u8,
    pub cur_temperature_underside: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 14;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        work_status: b[2],
        work_hour: b[7],
        work_minute: b[8],
        work_mode: b[10],
        temperature: b[11],
        underside_tube_temp: b[13],
        cur_temperature_above: b[10],
        cur_temperature_underside: b[12],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "mb4 status");
    let _ = write!(w, " work_status={}", st.work_status);
    let _ = write!(w, " work_hour={}", st.work_hour);
    let _ = write!(w, " work_minute={}", st.work_minute);
    let _ = write!(w, " work_mode={}", st.work_mode);
    let _ = write!(w, " temperature={}", st.temperature);
    let _ = write!(w, " underside_tube_temp={}", st.underside_tube_temp);
    let _ = write!(w, " cur_temperature_above={}", st.cur_temperature_above);
    let _ = write!(
        w,
        " cur_temperature_underside={}",
        st.cur_temperature_underside
    );
    true
}
