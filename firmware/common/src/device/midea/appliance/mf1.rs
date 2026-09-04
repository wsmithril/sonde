//! Midea (type `F1`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_F1_*.lua` (`binToModel`). Byte offsets are the status body
//! (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `F1` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub mode: u8,
    pub error_code: u8,
    pub response_type: u8,
    pub work_status: u8,
    pub step_status: u8,
    pub work_step: u8,
    pub cup_cap_status: u8,
    pub cup_body_status: u8,
    pub cur_work_time: u8,
    pub cur_temperature: u8,
    pub cur_work_speed: u8,
    pub temperature_reserve_hot: u8,
    pub temperature_reserve_warm: u8,
    pub time_reserve_finish: u8,
    pub time_reserve_work: u8,
    pub time_reserve_warm: u8,
    pub code_i_d: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 27;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        mode: b[4],
        error_code: b[8],
        response_type: b[9],
        work_status: b[10],
        step_status: b[11],
        work_step: b[12],
        cup_cap_status: b[13],
        cup_body_status: b[14],
        cur_work_time: b[15],
        cur_temperature: b[17],
        cur_work_speed: b[18],
        temperature_reserve_hot: b[19],
        temperature_reserve_warm: b[20],
        time_reserve_finish: b[21],
        time_reserve_work: b[23],
        time_reserve_warm: b[25],
        code_i_d: b[26],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "F1 status");
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " response_type={}", st.response_type);
    let _ = write!(w, " work_status={}", st.work_status);
    let _ = write!(w, " step_status={}", st.step_status);
    let _ = write!(w, " work_step={}", st.work_step);
    let _ = write!(w, " cup_cap_status={}", st.cup_cap_status);
    let _ = write!(w, " cup_body_status={}", st.cup_body_status);
    let _ = write!(w, " cur_work_time={}", st.cur_work_time);
    let _ = write!(w, " cur_temperature={}", st.cur_temperature);
    let _ = write!(w, " cur_work_speed={}", st.cur_work_speed);
    let _ = write!(w, " temperature_reserve_hot={}", st.temperature_reserve_hot);
    let _ = write!(
        w,
        " temperature_reserve_warm={}",
        st.temperature_reserve_warm
    );
    let _ = write!(w, " time_reserve_finish={}", st.time_reserve_finish);
    let _ = write!(w, " time_reserve_work={}", st.time_reserve_work);
    let _ = write!(w, " time_reserve_warm={}", st.time_reserve_warm);
    let _ = write!(w, " code_i_d={}", st.code_i_d);
    true
}
