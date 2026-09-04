//! Midea (type `B0`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_B0_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `B0` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub mode: u8,
    pub minutes: u8,
    pub second: u8,
    pub work_stage: u8,
    pub error_code: u8,
    pub tips_code: u8,
    pub maintain: u8,
    pub fire_power: u8,
    pub brittle_fire_power: u8,
    pub temp_pure_ferment: u8,
    pub clean_type: u8,
    pub temp_fast_steam: u8,
    pub temp_bake_or_ferment: u8,
    pub steam_time: u8,
    pub weight: u8,
    pub work_status: u8,
}

/// Status-body minimum length (the highest byte the decoder reads).
const S_MIN_LEN: usize = 16;

/// Parse the status body per the Lua's byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        mode: b[1],
        minutes: b[2],
        second: b[3],
        work_stage: b[4],
        error_code: b[5],
        tips_code: b[6],
        maintain: b[7],
        fire_power: b[14],
        brittle_fire_power: b[14],
        temp_pure_ferment: b[14],
        clean_type: b[14],
        temp_fast_steam: b[14],
        temp_bake_or_ferment: b[14],
        steam_time: b[15],
        weight: b[15],
        work_status: b[0] & 0x7F,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "B0 status");
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " minutes={}", st.minutes);
    let _ = write!(w, " second={}", st.second);
    let _ = write!(w, " work_stage={}", st.work_stage);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " tips_code={}", st.tips_code);
    let _ = write!(w, " maintain={}", st.maintain);
    let _ = write!(w, " fire_power={}", st.fire_power);
    let _ = write!(w, " brittle_fire_power={}", st.brittle_fire_power);
    let _ = write!(w, " temp_pure_ferment={}", st.temp_pure_ferment);
    let _ = write!(w, " clean_type={}", st.clean_type);
    let _ = write!(w, " temp_fast_steam={}", st.temp_fast_steam);
    let _ = write!(w, " temp_bake_or_ferment={}", st.temp_bake_or_ferment);
    let _ = write!(w, " steam_time={}", st.steam_time);
    let _ = write!(w, " weight={}", st.weight);
    let _ = write!(w, " work_status={}", st.work_status);
    true
}
