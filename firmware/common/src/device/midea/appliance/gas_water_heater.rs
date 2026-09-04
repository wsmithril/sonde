//! Midea (type `E3`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_E3_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `E3` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub temperature: u8,
    pub change_litre: u8,
    pub byte13: u8,
    pub byte14: u8,
    pub byte18: u8,
}

/// Status-body minimum length (the highest byte the decoder reads).
const S_MIN_LEN: usize = 19;

/// Parse the status body per the Lua's byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        temperature: b[6],
        change_litre: b[18],
        byte13: b[13],
        byte14: b[14],
        byte18: b[18],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "E3 status");
    let _ = write!(w, " temperature={}", st.temperature);
    let _ = write!(w, " change_litre={}", st.change_litre);
    let _ = write!(w, " byte13={}", st.byte13);
    let _ = write!(w, " byte14={}", st.byte14);
    let _ = write!(w, " byte18={}", st.byte18);
    true
}
