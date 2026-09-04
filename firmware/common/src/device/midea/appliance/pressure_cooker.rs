//! Midea (type `EC`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_EC_*.lua` (`binToModel`). Byte offsets are the status body
//! (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `EC` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub cmd_code: u8,
    pub taste: u8,
    pub pressure: u8,
    pub fire_level: u8,
    pub rice_type: u8,
    pub work_status: u8,
    pub work_flag: u8,
    pub temperature_top: u8,
    pub temperature_bottom: u8,
    pub time_reserve_hr: u8,
    pub time_reserve_min: u8,
    pub time_warm_hr: u8,
    pub time_warm_min: u8,
    pub time_work_hr: u8,
    pub time_work_min: u8,
    pub error_code: u8,
    pub time_pressurize_hr: u8,
    pub time_pressurize_min: u8,
    pub time_reserve_setting_hr: u8,
    pub time_reserve_setting_min: u8,
    pub time_work_setting_hr: u8,
    pub time_work_setting_min: u8,
    pub open_cap: u8,
    pub water_check: u8,
    pub zero_press: u8,
    pub inside_pot_status: u8,
    pub balance_status: u8,
    pub boil_status: u8,
    pub pause_open_cap: u8,
    pub press_switch: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 34;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        cmd_code: b[6],
        taste: b[9],
        pressure: b[10],
        fire_level: b[11],
        rice_type: b[12],
        work_status: b[14],
        work_flag: b[16],
        temperature_top: b[18],
        temperature_bottom: b[19],
        time_reserve_hr: b[20],
        time_reserve_min: b[21],
        time_warm_hr: b[26],
        time_warm_min: b[27],
        time_work_hr: b[28],
        time_work_min: b[29],
        error_code: b[33],
        time_pressurize_hr: b[14],
        time_pressurize_min: b[15],
        time_reserve_setting_hr: b[24],
        time_reserve_setting_min: b[25],
        time_work_setting_hr: b[26],
        time_work_setting_min: b[27],
        open_cap: b[23] & 0x01,
        water_check: (b[23] >> 1) & 0x01,
        zero_press: (b[23] >> 2) & 0x01,
        inside_pot_status: (b[23] >> 3) & 0x01,
        balance_status: (b[23] >> 4) & 0x01,
        boil_status: (b[23] >> 5) & 0x01,
        pause_open_cap: (b[23] >> 6) & 0x01,
        press_switch: (b[23] >> 7) & 0x01,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "EC status");
    let _ = write!(w, " cmd_code={}", st.cmd_code);
    let _ = write!(w, " taste={}", st.taste);
    let _ = write!(w, " pressure={}", st.pressure);
    let _ = write!(w, " fire_level={}", st.fire_level);
    let _ = write!(w, " rice_type={}", st.rice_type);
    let _ = write!(w, " work_status={}", st.work_status);
    let _ = write!(w, " work_flag={}", st.work_flag);
    let _ = write!(w, " temperature_top={}", st.temperature_top);
    let _ = write!(w, " temperature_bottom={}", st.temperature_bottom);
    let _ = write!(w, " time_reserve_hr={}", st.time_reserve_hr);
    let _ = write!(w, " time_reserve_min={}", st.time_reserve_min);
    let _ = write!(w, " time_warm_hr={}", st.time_warm_hr);
    let _ = write!(w, " time_warm_min={}", st.time_warm_min);
    let _ = write!(w, " time_work_hr={}", st.time_work_hr);
    let _ = write!(w, " time_work_min={}", st.time_work_min);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " time_pressurize_hr={}", st.time_pressurize_hr);
    let _ = write!(w, " time_pressurize_min={}", st.time_pressurize_min);
    let _ = write!(w, " time_reserve_setting_hr={}", st.time_reserve_setting_hr);
    let _ = write!(
        w,
        " time_reserve_setting_min={}",
        st.time_reserve_setting_min
    );
    let _ = write!(w, " time_work_setting_hr={}", st.time_work_setting_hr);
    let _ = write!(w, " time_work_setting_min={}", st.time_work_setting_min);
    let _ = write!(w, " open_cap={}", st.open_cap);
    let _ = write!(w, " water_check={}", st.water_check);
    let _ = write!(w, " zero_press={}", st.zero_press);
    let _ = write!(w, " inside_pot_status={}", st.inside_pot_status);
    let _ = write!(w, " balance_status={}", st.balance_status);
    let _ = write!(w, " boil_status={}", st.boil_status);
    let _ = write!(w, " pause_open_cap={}", st.pause_open_cap);
    let _ = write!(w, " press_switch={}", st.press_switch);
    true
}
