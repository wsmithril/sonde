//! Midea (type `9A`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_9A_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `9A` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub workstatus: u8,
    pub lock: u8,
    pub furnace_light: u8,
    pub hour: u8,
    pub minutes: u8,
    pub second: u8,
    pub mode: u8,
    pub fire: u8,
    pub weight: u8,
    pub temperature: u16,
    pub cur_temp: u16,
}

/// Status-body minimum length (the highest byte the decoder reads).
const S_MIN_LEN: usize = 17;

/// Parse the status body per the Lua's byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        workstatus: b[2],
        lock: b[3],
        furnace_light: b[4],
        hour: b[7],
        minutes: b[8],
        second: b[9],
        mode: b[10],
        fire: b[15],
        weight: b[16],
        temperature: ((b[11] as u16) << 8),
        cur_temp: ((b[10] as u16) << 8),
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "9A status");
    let _ = write!(w, " workstatus={}", st.workstatus);
    let _ = write!(w, " lock={}", st.lock);
    let _ = write!(w, " furnace_light={}", st.furnace_light);
    let _ = write!(w, " hour={}", st.hour);
    let _ = write!(w, " minutes={}", st.minutes);
    let _ = write!(w, " second={}", st.second);
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " fire={}", st.fire);
    let _ = write!(w, " weight={}", st.weight);
    let _ = write!(w, " temperature={}", st.temperature);
    let _ = write!(w, " cur_temp={}", st.cur_temp);
    true
}
