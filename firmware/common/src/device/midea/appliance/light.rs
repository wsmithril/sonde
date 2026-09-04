//! Midea (type `13`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_13_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `13` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub cmd_type: u8,
    pub result: u8,
    pub brightness: u8,
    pub color_temperature: u8,
    pub scene_light: u8,
    pub delay_light_off: u8,
    pub color_red: u8,
    pub color_green: u8,
    pub color_blue: u8,
    pub power_value: u8,
    pub life_brightness: u8,
    pub life_color_temperature: u8,
    pub read_brightness: u8,
    pub read_color_temperature: u8,
    pub mild_brightness: u8,
    pub mild_color_temperature: u8,
    pub film_brightness: u8,
    pub film_color_temperature: u8,
    pub light_brightness: u8,
    pub light_color_temperature: u8,
}

/// Status-body minimum length (the highest byte the decoder reads).
const S_MIN_LEN: usize = 19;

/// Parse the status body per the Lua's byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        cmd_type: b[0],
        result: b[1],
        brightness: b[1],
        color_temperature: b[2],
        scene_light: b[3],
        delay_light_off: b[4],
        color_red: b[5],
        color_green: b[6],
        color_blue: b[7],
        power_value: b[8],
        life_brightness: b[9],
        life_color_temperature: b[10],
        read_brightness: b[11],
        read_color_temperature: b[12],
        mild_brightness: b[13],
        mild_color_temperature: b[14],
        film_brightness: b[15],
        film_color_temperature: b[16],
        light_brightness: b[17],
        light_color_temperature: b[18],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "13 status");
    let _ = write!(w, " cmd_type={}", st.cmd_type);
    let _ = write!(w, " result={}", st.result);
    let _ = write!(w, " brightness={}", st.brightness);
    let _ = write!(w, " color_temperature={}", st.color_temperature);
    let _ = write!(w, " scene_light={}", st.scene_light);
    let _ = write!(w, " delay_light_off={}", st.delay_light_off);
    let _ = write!(w, " color_red={}", st.color_red);
    let _ = write!(w, " color_green={}", st.color_green);
    let _ = write!(w, " color_blue={}", st.color_blue);
    let _ = write!(w, " power_value={}", st.power_value);
    let _ = write!(w, " life_brightness={}", st.life_brightness);
    let _ = write!(w, " life_color_temperature={}", st.life_color_temperature);
    let _ = write!(w, " read_brightness={}", st.read_brightness);
    let _ = write!(w, " read_color_temperature={}", st.read_color_temperature);
    let _ = write!(w, " mild_brightness={}", st.mild_brightness);
    let _ = write!(w, " mild_color_temperature={}", st.mild_color_temperature);
    let _ = write!(w, " film_brightness={}", st.film_brightness);
    let _ = write!(w, " film_color_temperature={}", st.film_color_temperature);
    let _ = write!(w, " light_brightness={}", st.light_brightness);
    let _ = write!(w, " light_color_temperature={}", st.light_color_temperature);
    true
}
