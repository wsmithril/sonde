//! Midea (type `B6`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_B6_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `B6` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub intelligent: u8,
    pub gear: u8,
    pub errorcode: u8,
    pub power: u8,
    pub light: u8,
    pub minutes: u16,
}

/// Status-body minimum length (the highest byte the decoder reads).
const S_MIN_LEN: usize = 9;

/// Parse the status body per the Lua's byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        intelligent: b[0],
        gear: b[7],
        errorcode: b[8],
        power: b[3] & 0x0F,
        light: b[4] & 0x80,
        minutes: ((b[6] as u16) << 8),
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "B6 status");
    let _ = write!(w, " intelligent={}", st.intelligent);
    let _ = write!(w, " gear={}", st.gear);
    let _ = write!(w, " errorcode={}", st.errorcode);
    let _ = write!(w, " power={}", st.power);
    let _ = write!(w, " light={}", st.light);
    let _ = write!(w, " minutes={}", st.minutes);
    true
}
