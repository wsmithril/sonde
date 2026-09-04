//! Midea (type `DA`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_DA_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `DA` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub power: u8,
    pub running_work_status: u8,
    pub mode: u8,
    pub program: u8,
    pub wash_time: u8,
    pub remain_time: u8,
    pub error_code: u8,
    pub wash_level: u8,
    pub wash_strength: u8,
    pub rinse_count: u8,
    pub temperature: u8,
}

/// Status-body minimum length (the highest byte the decoder reads).
const S_MIN_LEN: usize = 25;

/// Parse the status body per the Lua's byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        power: b[1],
        running_work_status: b[2],
        mode: b[3],
        program: b[4],
        wash_time: b[9],
        remain_time: b[17],
        error_code: b[24],
        wash_level: b[5] & 0x0F,
        wash_strength: b[6] & 0x0F,
        rinse_count: b[10] & 0x0F,
        temperature: b[15] & 0x0F,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "DA status");
    let _ = write!(w, " power={}", st.power);
    let _ = write!(w, " running_work_status={}", st.running_work_status);
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " program={}", st.program);
    let _ = write!(w, " wash_time={}", st.wash_time);
    let _ = write!(w, " remain_time={}", st.remain_time);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " wash_level={}", st.wash_level);
    let _ = write!(w, " wash_strength={}", st.wash_strength);
    let _ = write!(w, " rinse_count={}", st.rinse_count);
    let _ = write!(w, " temperature={}", st.temperature);
    true
}
