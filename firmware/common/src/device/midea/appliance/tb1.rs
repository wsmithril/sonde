//! Midea (type `B1`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_B1_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `B1` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub workstatus: u8,
    pub mode: u8,
    pub hour: u8,
    pub minutes: u8,
    pub cur_temp: u8,
    pub error_code: u8,
    pub temperature: u8,
    pub lock: u8,
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
        workstatus: b[0],
        mode: b[1],
        hour: b[2],
        minutes: b[3],
        cur_temp: b[4],
        error_code: b[5],
        temperature: b[8],
        lock: b[16],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "B1 status");
    let _ = write!(w, " workstatus={}", st.workstatus);
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " hour={}", st.hour);
    let _ = write!(w, " minutes={}", st.minutes);
    let _ = write!(w, " cur_temp={}", st.cur_temp);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " temperature={}", st.temperature);
    let _ = write!(w, " lock={}", st.lock);
    true
}
