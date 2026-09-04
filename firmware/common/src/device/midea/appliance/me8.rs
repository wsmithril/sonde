//! Midea (type `E8`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_E8_*.lua` (`binToModel`). Byte offsets are the status body
//! (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `E8` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub power: u8,
    pub stage1: u8,
    pub stage1_time: u8,
    pub stage2: u8,
    pub stage2_time: u8,
    pub stage3: u8,
    pub stage3_time: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 18;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        power: b[8],
        stage1: b[9],
        stage1_time: b[11],
        stage2: b[12],
        stage2_time: b[14],
        stage3: b[15],
        stage3_time: b[17],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "E8 status");
    let _ = write!(w, " power={}", st.power);
    let _ = write!(w, " stage1={}", st.stage1);
    let _ = write!(w, " stage1_time={}", st.stage1_time);
    let _ = write!(w, " stage2={}", st.stage2);
    let _ = write!(w, " stage2_time={}", st.stage2_time);
    let _ = write!(w, " stage3={}", st.stage3);
    let _ = write!(w, " stage3_time={}", st.stage3_time);
    true
}
