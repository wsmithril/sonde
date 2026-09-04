//! Midea (type `EF`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_EF_*.lua` (`binToModel`). Byte offsets are the status body
//! (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `EF` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub work_status: u8,
    pub error_code: u8,
    pub response_type: u8,
    pub cmd_i_d: u8,
    pub work_step: u8,
    pub process_status: u8,
    pub time_work_hr: u8,
    pub time_work_min: u8,
    pub time_max: u8,
    pub temperature_setting: u8,
    pub temperature_current: u8,
    pub reserve: u8,
    pub warm: u8,
    pub drink_style: u8,
    pub cmd_code: u16,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 20;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        work_status: b[8],
        error_code: b[9],
        response_type: b[10],
        cmd_i_d: b[11],
        work_step: b[13],
        process_status: b[14],
        time_work_hr: b[15],
        time_work_min: b[16],
        time_max: b[17],
        temperature_setting: b[18],
        temperature_current: b[19],
        reserve: b[12] & 0x01,
        warm: b[12] & 0x02,
        drink_style: b[12] & 0x04,
        cmd_code: (b[5] as u16) << 8,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "EF status");
    let _ = write!(w, " work_status={}", st.work_status);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " response_type={}", st.response_type);
    let _ = write!(w, " cmd_i_d={}", st.cmd_i_d);
    let _ = write!(w, " work_step={}", st.work_step);
    let _ = write!(w, " process_status={}", st.process_status);
    let _ = write!(w, " time_work_hr={}", st.time_work_hr);
    let _ = write!(w, " time_work_min={}", st.time_work_min);
    let _ = write!(w, " time_max={}", st.time_max);
    let _ = write!(w, " temperature_setting={}", st.temperature_setting);
    let _ = write!(w, " temperature_current={}", st.temperature_current);
    let _ = write!(w, " reserve={}", st.reserve);
    let _ = write!(w, " warm={}", st.warm);
    let _ = write!(w, " drink_style={}", st.drink_style);
    let _ = write!(w, " cmd_code={}", st.cmd_code);
    true
}
