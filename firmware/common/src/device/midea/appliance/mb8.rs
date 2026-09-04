//! Midea mb8 (type `B8`) status decode, cross-checked against the
//! manufacturer's Lua `T_0000_B8_*.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `B8` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub work_status: u8,
    pub control_mode: u8,
    pub move_direction: u8,
    pub work_mode: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 7;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        work_status: b[2],
        control_mode: b[4],
        move_direction: b[5],
        work_mode: b[6],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "mb8 status");
    let _ = write!(w, " work_status={}", st.work_status);
    let _ = write!(w, " control_mode={}", st.control_mode);
    let _ = write!(w, " move_direction={}", st.move_direction);
    let _ = write!(w, " work_mode={}", st.work_mode);
    true
}
