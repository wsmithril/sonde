//! Midea (type `E1`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_E1_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `E1` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub work_status: u8,
    pub mode: u8,
    pub left_time: u8,
    pub wash_stage: u8,
    pub error_code: u8,
    pub temperature: u8,
}

/// Status-body minimum length (the highest byte the decoder reads).
const S_MIN_LEN: usize = 12;

/// Parse the status body per the Lua's byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        work_status: b[1],
        mode: b[2],
        left_time: b[6],
        wash_stage: b[9],
        error_code: b[10],
        temperature: b[11],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "E1 status");
    let _ = write!(w, " work_status={}", st.work_status);
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " left_time={}", st.left_time);
    let _ = write!(w, " wash_stage={}", st.wash_stage);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " temperature={}", st.temperature);
    true
}
