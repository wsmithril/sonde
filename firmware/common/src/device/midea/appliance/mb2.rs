//! Midea mb2 (type `B2`) status decode, cross-checked against the
//! manufacturer's Lua `T_0000_B2_*.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `B2` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub work_status: u8,
    pub work_mode: u8,
    pub work_hour: u8,
    pub work_minute: u8,
    pub temperature: u8,
    pub lock: u8,
    pub box_state: u8,
    pub water_state: u8,
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
        work_status: b[0],
        work_mode: b[1],
        work_hour: b[2],
        work_minute: b[3],
        temperature: b[4],
        lock: b[16],
        box_state: b[6] & 0x01,
        water_state: b[6] & 0x02,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "mb2 status");
    let _ = write!(w, " work_status={}", st.work_status);
    let _ = write!(w, " work_mode={}", st.work_mode);
    let _ = write!(w, " work_hour={}", st.work_hour);
    let _ = write!(w, " work_minute={}", st.work_minute);
    let _ = write!(w, " temperature={}", st.temperature);
    let _ = write!(w, " lock={}", st.lock);
    let _ = write!(w, " box_state={}", st.box_state);
    let _ = write!(w, " water_state={}", st.water_state);
    true
}
