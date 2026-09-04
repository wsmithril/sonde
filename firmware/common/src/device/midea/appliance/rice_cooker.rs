//! Midea (type `EA`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_EA_*.lua` (`binToModel`). Byte offsets are the status body
//! (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `EA` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub mode: u8,
    pub workstatus: u8,
    pub error_code: u8,
    pub order_hour: u8,
    pub order_min: u8,
    pub left_hour: u8,
    pub left_min: u8,
    pub warm_hour: u8,
    pub warm_min: u8,
    pub mouth_feel: u8,
    pub rice_type: u8,
    pub voltage: u8,
    pub indoor_temperature: u8,
    pub top_temperature: u8,
    pub bottom_temperature: u8,
    pub work_stage: u8,
    pub work_flag: u8,
    pub rice_level: u8,
    pub rice_cup_number: u8,
    pub step_expect_time: u8,
    pub step_actual_time: u8,
    pub storage_volume_level: u8,
    pub storage_temp: u8,
    pub storage_humodity: u8,
    pub storage_expect_cup: u8,
    pub storage_type: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 42;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        mode: b[4],
        workstatus: b[8],
        error_code: b[9],
        order_hour: b[10],
        order_min: b[11],
        left_hour: b[12],
        left_min: b[13],
        warm_hour: b[22],
        warm_min: b[23],
        mouth_feel: b[14],
        rice_type: b[15],
        voltage: b[24],
        indoor_temperature: b[26],
        top_temperature: b[20],
        bottom_temperature: b[21],
        work_stage: b[19],
        work_flag: b[18],
        rice_level: b[17],
        rice_cup_number: b[32],
        step_expect_time: b[33],
        step_actual_time: b[35],
        storage_volume_level: b[37],
        storage_temp: b[38],
        storage_humodity: b[39],
        storage_expect_cup: b[40],
        storage_type: b[41],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "EA status");
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " workstatus={}", st.workstatus);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " order_hour={}", st.order_hour);
    let _ = write!(w, " order_min={}", st.order_min);
    let _ = write!(w, " left_hour={}", st.left_hour);
    let _ = write!(w, " left_min={}", st.left_min);
    let _ = write!(w, " warm_hour={}", st.warm_hour);
    let _ = write!(w, " warm_min={}", st.warm_min);
    let _ = write!(w, " mouth_feel={}", st.mouth_feel);
    let _ = write!(w, " rice_type={}", st.rice_type);
    let _ = write!(w, " voltage={}", st.voltage);
    let _ = write!(w, " indoor_temperature={}", st.indoor_temperature);
    let _ = write!(w, " top_temperature={}", st.top_temperature);
    let _ = write!(w, " bottom_temperature={}", st.bottom_temperature);
    let _ = write!(w, " work_stage={}", st.work_stage);
    let _ = write!(w, " work_flag={}", st.work_flag);
    let _ = write!(w, " rice_level={}", st.rice_level);
    let _ = write!(w, " rice_cup_number={}", st.rice_cup_number);
    let _ = write!(w, " step_expect_time={}", st.step_expect_time);
    let _ = write!(w, " step_actual_time={}", st.step_actual_time);
    let _ = write!(w, " storage_volume_level={}", st.storage_volume_level);
    let _ = write!(w, " storage_temp={}", st.storage_temp);
    let _ = write!(w, " storage_humodity={}", st.storage_humodity);
    let _ = write!(w, " storage_expect_cup={}", st.storage_expect_cup);
    let _ = write!(w, " storage_type={}", st.storage_type);
    true
}
