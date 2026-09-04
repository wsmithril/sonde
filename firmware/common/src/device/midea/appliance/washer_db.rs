//! Midea (type `DB`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_DB_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `DB` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub power: u8,
    pub running_work_status: u8,
    pub mode: u8,
    pub program: u8,
    pub water_level: u8,
    pub temperature: u8,
    pub dehydration_speed: u8,
    pub dehydration_min: u8,
    pub byte13: u8,
    pub remain_time: u8,
    pub error_code: u8,
    pub byte16: u8,
    pub expert_step: u8,
    pub soak_count: u8,
}

/// Status-body minimum length (the highest byte the decoder reads).
const S_MIN_LEN: usize = 26;

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
        water_level: b[5],
        temperature: b[7],
        dehydration_speed: b[8],
        dehydration_min: b[10],
        byte13: b[13],
        remain_time: b[17],
        error_code: b[24],
        byte16: b[25],
        expert_step: b[19],
        soak_count: (b[6] >> 4) & 0x0F,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "DB status");
    let _ = write!(w, " power={}", st.power);
    let _ = write!(w, " running_work_status={}", st.running_work_status);
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " program={}", st.program);
    let _ = write!(w, " water_level={}", st.water_level);
    let _ = write!(w, " temperature={}", st.temperature);
    let _ = write!(w, " dehydration_speed={}", st.dehydration_speed);
    let _ = write!(w, " dehydration_min={}", st.dehydration_min);
    let _ = write!(w, " byte13={}", st.byte13);
    let _ = write!(w, " remain_time={}", st.remain_time);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " byte16={}", st.byte16);
    let _ = write!(w, " expert_step={}", st.expert_step);
    let _ = write!(w, " soak_count={}", st.soak_count);
    true
}
