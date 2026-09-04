//! Midea (type `E7`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_E7_*.lua` (`binToModel`). Byte offsets are the status body
//! (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `E7` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub cmd_code_low: u8,
    pub cmd_code_high: u8,
    pub response_type: u8,
    pub work_status: u8,
    pub time_running_hr: u8,
    pub time_running_min: u8,
    pub time_surplus_hr: u8,
    pub time_surplus_min: u8,
    pub time_reserve_hr: u8,
    pub time_reserve_min: u8,
    pub fire_level: u8,
    pub definite_time_hr: u8,
    pub definite_time_min: u8,
    pub work_stage: u8,
    pub error_code: u8,
    pub function_no: u16,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 24;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        cmd_code_low: b[7],
        cmd_code_high: b[8],
        response_type: b[9],
        work_status: b[10],
        time_running_hr: b[13],
        time_running_min: b[14],
        time_surplus_hr: b[15],
        time_surplus_min: b[16],
        time_reserve_hr: b[17],
        time_reserve_min: b[18],
        fire_level: b[19],
        definite_time_hr: b[20],
        definite_time_min: b[21],
        work_stage: b[22],
        error_code: b[23],
        function_no: (b[11] as u16) << 8,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "E7 status");
    let _ = write!(w, " cmd_code_low={}", st.cmd_code_low);
    let _ = write!(w, " cmd_code_high={}", st.cmd_code_high);
    let _ = write!(w, " response_type={}", st.response_type);
    let _ = write!(w, " work_status={}", st.work_status);
    let _ = write!(w, " time_running_hr={}", st.time_running_hr);
    let _ = write!(w, " time_running_min={}", st.time_running_min);
    let _ = write!(w, " time_surplus_hr={}", st.time_surplus_hr);
    let _ = write!(w, " time_surplus_min={}", st.time_surplus_min);
    let _ = write!(w, " time_reserve_hr={}", st.time_reserve_hr);
    let _ = write!(w, " time_reserve_min={}", st.time_reserve_min);
    let _ = write!(w, " fire_level={}", st.fire_level);
    let _ = write!(w, " definite_time_hr={}", st.definite_time_hr);
    let _ = write!(w, " definite_time_min={}", st.definite_time_min);
    let _ = write!(w, " work_stage={}", st.work_stage);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " function_no={}", st.function_no);
    true
}
