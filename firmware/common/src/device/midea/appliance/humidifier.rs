//! Midea humidifier (type `FD`) status decode, cross-checked against the
//! manufacturer's Lua `T_0000_FD_*.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `FD` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub fanspeed: u8,
    pub set_humidity: u8,
    pub current_humidity: u8,
    pub tank_status: u8,
    pub power: u8,
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
        fanspeed: b[3],
        set_humidity: b[7],
        current_humidity: b[16],
        tank_status: b[10],
        power: b[1] & 0x01,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "humidifier status");
    let _ = write!(w, " fanspeed={}", st.fanspeed);
    let _ = write!(w, " set_humidity={}", st.set_humidity);
    let _ = write!(w, " current_humidity={}", st.current_humidity);
    let _ = write!(w, " tank_status={}", st.tank_status);
    let _ = write!(w, " power={}", st.power);
    true
}
