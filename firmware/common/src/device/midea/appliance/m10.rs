//! Midea m10 (type `10`) status decode, cross-checked against the
//! manufacturer's Lua `T_0000_10_*.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `10` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub power: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 2;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status { power: b[1] })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "m10 status");
    let _ = write!(w, " power={}", st.power);
    true
}
