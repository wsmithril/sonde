//! Midea (type `E9`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_E9_*.lua` (`binToModel`). Byte offsets are the status body
//! (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `E9` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub cmd_control_code: u8,
    pub response_type: u8,
    pub volume: u8,
    pub color: u8,
    pub dosing: u8,
    pub work_status: u8,
    pub work_stage: u8,
    pub botton_temperature: u8,
    pub time_reserve_min: u8,
    pub time_reserve_hr: u8,
    pub time_work_min: u8,
    pub time_work_hr: u8,
    pub time_warm_min: u8,
    pub time_warm_hr: u8,
    pub error_code: u8,
    pub cmd_query_code_low: u8,
    pub cmd_query_code_high: u8,
    pub product_volume: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 22;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        cmd_control_code: b[6],
        response_type: b[8],
        volume: b[9],
        color: b[10],
        dosing: b[11],
        work_status: b[12],
        work_stage: b[13],
        botton_temperature: b[14],
        time_reserve_min: b[15],
        time_reserve_hr: b[16],
        time_work_min: b[17],
        time_work_hr: b[18],
        time_warm_min: b[19],
        time_warm_hr: b[20],
        error_code: b[21],
        cmd_query_code_low: b[6],
        cmd_query_code_high: b[7],
        product_volume: b[15],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "E9 status");
    let _ = write!(w, " cmd_control_code={}", st.cmd_control_code);
    let _ = write!(w, " response_type={}", st.response_type);
    let _ = write!(w, " volume={}", st.volume);
    let _ = write!(w, " color={}", st.color);
    let _ = write!(w, " dosing={}", st.dosing);
    let _ = write!(w, " work_status={}", st.work_status);
    let _ = write!(w, " work_stage={}", st.work_stage);
    let _ = write!(w, " botton_temperature={}", st.botton_temperature);
    let _ = write!(w, " time_reserve_min={}", st.time_reserve_min);
    let _ = write!(w, " time_reserve_hr={}", st.time_reserve_hr);
    let _ = write!(w, " time_work_min={}", st.time_work_min);
    let _ = write!(w, " time_work_hr={}", st.time_work_hr);
    let _ = write!(w, " time_warm_min={}", st.time_warm_min);
    let _ = write!(w, " time_warm_hr={}", st.time_warm_hr);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " cmd_query_code_low={}", st.cmd_query_code_low);
    let _ = write!(w, " cmd_query_code_high={}", st.cmd_query_code_high);
    let _ = write!(w, " product_volume={}", st.product_volume);
    true
}
