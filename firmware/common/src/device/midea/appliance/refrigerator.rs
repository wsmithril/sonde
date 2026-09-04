//! Midea refrigerator (type `CA`) status decode, cross-checked against the
//! manufacturer's Lua `T_0000_CA_*.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `CA` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub variable_mode: u8,
    pub refrigeration_power: u8,
    pub l_variable_power: u8,
    pub r_variable_power: u8,
    pub freezing_power: u8,
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
        variable_mode: b[5],
        refrigeration_power: b[6] & 0x01,
        l_variable_power: b[6] & 0x04,
        r_variable_power: b[6] & 0x08,
        freezing_power: b[6] & 0x10,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "refrigerator status");
    let _ = write!(w, " variable_mode={}", st.variable_mode);
    let _ = write!(w, " refrigeration_power={}", st.refrigeration_power);
    let _ = write!(w, " l_variable_power={}", st.l_variable_power);
    let _ = write!(w, " r_variable_power={}", st.r_variable_power);
    let _ = write!(w, " freezing_power={}", st.freezing_power);
    true
}
