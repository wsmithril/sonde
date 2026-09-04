//! Midea mcc (type `CC`) status decode, cross-checked against the
//! manufacturer's Lua `T_0000_CC_*.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `CC` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub fanspeed: u8,
    pub temperature: u8,
    pub swing_u_d_site: u8,
    pub swing_l_r_site: u8,
    pub power: u8,
    pub mode: u8,
    pub exhaust: u8,
    pub swing_u_d_switch: u8,
    pub p_t_c: u8,
    pub eco: u8,
    pub p_t_c_setting: u8,
    pub sleep_switch: u8,
    pub digit_display_switch: u8,
    pub swing_l_r_switch: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 18;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        fanspeed: b[2],
        temperature: b[3],
        swing_u_d_site: b[9],
        swing_l_r_site: b[17],
        power: b[1] & 0x80,
        mode: b[1] & 0x1F,
        exhaust: b[13] & 0x08,
        swing_u_d_switch: b[13] & 0x04,
        p_t_c: b[13] & 0x02,
        eco: b[13] & 0x01,
        p_t_c_setting: b[14] & 0x60,
        sleep_switch: b[14] & 0x10,
        digit_display_switch: b[14] & 0x08,
        swing_l_r_switch: b[14] & 0x01,
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "mcc status");
    let _ = write!(w, " fanspeed={}", st.fanspeed);
    let _ = write!(w, " temperature={}", st.temperature);
    let _ = write!(w, " swing_u_d_site={}", st.swing_u_d_site);
    let _ = write!(w, " swing_l_r_site={}", st.swing_l_r_site);
    let _ = write!(w, " power={}", st.power);
    let _ = write!(w, " mode={}", st.mode);
    let _ = write!(w, " exhaust={}", st.exhaust);
    let _ = write!(w, " swing_u_d_switch={}", st.swing_u_d_switch);
    let _ = write!(w, " p_t_c={}", st.p_t_c);
    let _ = write!(w, " eco={}", st.eco);
    let _ = write!(w, " p_t_c_setting={}", st.p_t_c_setting);
    let _ = write!(w, " sleep_switch={}", st.sleep_switch);
    let _ = write!(w, " digit_display_switch={}", st.digit_display_switch);
    let _ = write!(w, " swing_l_r_switch={}", st.swing_l_r_switch);
    true
}
