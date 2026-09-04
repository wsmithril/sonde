//! Midea (type `17`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_17_*.lua` (`binToModel`). Byte offsets are the status body
//! (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `17` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub byte0: u8,
    pub byte1: u8,
    pub byte2: u8,
    pub error_code: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 4;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        byte0: b[0],
        byte1: b[1],
        byte2: b[2],
        error_code: b[3],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "17 status");
    let _ = write!(w, " byte0={}", st.byte0);
    let _ = write!(w, " byte1={}", st.byte1);
    let _ = write!(w, " byte2={}", st.byte2);
    let _ = write!(w, " error_code={}", st.error_code);
    true
}
