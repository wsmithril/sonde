//! Midea air-conditioner control: build the 0x40 control / 0x41 query appliance
//! frames and parse the 0xC0 status reply. Ported from midea-ble-go
//! (`internal/ac/appliance.go`).
//!
//! The appliance frame is the business-layer body: wrap it with
//! [`super::frame::encode_biz`]`(BIZ_TYPE_AC, frame)`, encrypt under the ECDH
//! sessionKey, then [`super::frame::encode_security`]`(C4, …)` and
//! [`super::frame::encode_conn`]`(T3, …)` before writing to GATT `0xFFA1`.
//!
//! Temperatures are integer tenths of a degree (26.0 °C = 260) so the port stays
//! free of floating point. Not wired to any mode yet.
#![allow(dead_code)]

use super::frame::Frame;

/// Business-layer type for AC appliance frames.
pub const BIZ_TYPE_AC: u8 = 32;
const DEV_TYPE_AC: u8 = 0xAC;

// Operating modes.
pub const MODE_AUTO: u8 = 1;
pub const MODE_COOL: u8 = 2;
pub const MODE_DRY: u8 = 3;
pub const MODE_HEAT: u8 = 4;
pub const MODE_FAN: u8 = 5;
pub const MODE_SMART_DRY: u8 = 6;

// Fan speeds (Midea/Hualing BLE enum).
pub const WIND_LOW: u8 = 40;
pub const WIND_MID: u8 = 60;
pub const WIND_HIGH: u8 = 80;
pub const WIND_FULL: u8 = 100;
pub const WIND_AUTO: u8 = 102;

pub fn mode_name(m: u8) -> &'static str {
    match m {
        MODE_AUTO => "auto", MODE_COOL => "cool", MODE_DRY => "dry",
        MODE_HEAT => "heat", MODE_FAN => "fan", MODE_SMART_DRY => "smart_dry",
        _ => "?",
    }
}

pub fn wind_name(w: u8) -> &'static str {
    match w {
        WIND_LOW => "low", WIND_MID => "mid", WIND_HIGH => "high",
        WIND_FULL => "full", WIND_AUTO => "auto", _ => "?",
    }
}

/// CRC-8/854 table for the AC control frame (`internal/ac/appliance.go`).
#[rustfmt::skip]
const CRC8_854: [u8; 256] = [
    0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
    157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
    35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
    190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
    70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
    219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
    101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
    248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
    140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
    17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
    175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
    50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
    202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
    87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
    233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
    116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53,
];

fn crc8854(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |o, &b| CRC8_854[(o ^ b) as usize])
}

/// `(255 - Σb + 1) & 0xFF` — identical to the two's-complement checksum.
fn make_sum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, &x| a.wrapping_sub(x))
}

/// Round tenths-of-a-degree to whole degrees, clamped to 17..=30.
fn check_temp_val(tenths: i32) -> i32 {
    ((tenths + 5) / 10).clamp(17, 30)
}

/// Whether a tenths value carries a half degree.
fn is_half(tenths: i32) -> bool {
    tenths % 10 == 5
}

/// State encoded into a control frame. Defaults ([`AcState::new`]) mirror the
/// reference `NewACState`, so a frame built from a fresh state is byte-identical.
pub struct AcState {
    pub run_status: u8,
    pub control_source: u8,
    pub imode: u8,
    pub child_sleep_mode: u8,
    pub timing_type: u8,
    pub quick_chk_sts: u8,
    pub btn_sound: u8,
    pub mode: u8,
    pub temp_set: i32, // tenths of a degree
    pub temp_mode_switch: u8,
    pub wind_speed: u8,
    pub timing_is_valid: u8,
    pub cosy_wind: i32,
    pub left_up_down_wind: u8,
    pub right_up_down_wind: u8,
    pub left_left_right_wind: u8,
    pub right_left_right_wind: u8,
    pub cosy_sleep_mode: u8,
    pub alm_sleep: u8,
    pub power_save: u8,
    pub farce_wind: u8,
    pub strong: u8,
    pub energy_save: u8,
    pub body_sense: u8,
    pub wisdom_eye: u8,
    pub chg_of_air: u8,
    pub diy_func: u8,
    pub elec_heat: u8,
    pub elec_heat_forced: u8,
    pub clean_up_func: u8,
    pub eco_func: u8,
    pub sleep_func_state: u8,
    pub turbo_func_state: u8,
    pub against_cool: u8,
    pub night_light: u8,
    pub pmv: u8,
    pub dust_flow: u8,
    pub clean_fan_run_time: u8,
    pub sleep_temps: [i32; 10], // tenths
    pub comfort_sleep_time: u8,
    pub natural_wind: u8,
    pub temp_set2: i32, // tenths
    pub humidity: u8,
    pub down_wind: u8,
    pub cs_eco: u8,
    pub order: u8,
}

impl AcState {
    /// Legal defaults (cool 26.0 °C, auto fan, button sound on, sleep temps 26).
    pub fn new() -> Self {
        Self {
            run_status: 0, control_source: 1, imode: 0, child_sleep_mode: 0,
            timing_type: 0, quick_chk_sts: 0, btn_sound: 1,
            mode: MODE_COOL, temp_set: 260, temp_mode_switch: 0,
            wind_speed: WIND_AUTO, timing_is_valid: 0,
            cosy_wind: 0, left_up_down_wind: 0, right_up_down_wind: 0,
            left_left_right_wind: 0, right_left_right_wind: 0,
            cosy_sleep_mode: 0, alm_sleep: 0, power_save: 0, farce_wind: 0,
            strong: 0, energy_save: 0, body_sense: 0,
            wisdom_eye: 0, chg_of_air: 0, diy_func: 0, elec_heat: 0,
            elec_heat_forced: 0, clean_up_func: 0, eco_func: 0,
            sleep_func_state: 0, turbo_func_state: 0, against_cool: 0,
            night_light: 0, pmv: 0, dust_flow: 0, clean_fan_run_time: 0,
            sleep_temps: [260; 10], comfort_sleep_time: 10, natural_wind: 0,
            temp_set2: 260, humidity: 0, down_wind: 0, cs_eco: 0, order: 1,
        }
    }
}

impl Default for AcState {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the 37-byte AC control appliance frame (opcode 0x40). Returns `None`
/// when `temp_set` is not a whole or half degree.
pub fn build_control_frame(s: &AcState) -> Option<Frame> {
    let mut a = [0u8; 37];
    a[0] = 0xAA;
    a[2] = DEV_TYPE_AC;
    a[8] = 2;
    a[9] = 2;
    a[10] = 64;
    let control_source = 1u8; // forced by the reference

    a[11] = (s.btn_sound & 1) << 6 | (s.quick_chk_sts & 1) << 5 | (s.timing_type & 1) << 4
        | (s.child_sleep_mode & 1) << 3 | (s.imode & 1) << 2 | (control_source & 1) << 1
        | (s.run_status & 1);

    a[12] = (s.mode & 7) << 5;
    let u = s.temp_set;
    if (160..=300).contains(&u) {
        a[12] |= ((u / 10 - 16) & 15) as u8;
    }
    match u % 10 {
        0 => {}
        5 => a[12] |= 16,
        _ => return None,
    }

    a[13] = (s.timing_is_valid & 1) << 7 | (s.wind_speed & 127);

    // Timing default path (timing_type == 0): both timers cleared.
    if s.timing_type == 1 {
        // Absolute-timer path is unused by the simple controls; encode zeros.
        a[14] = 0;
        a[15] = 0;
        a[16] = 0;
    } else {
        a[14] = 127;
        a[15] = 127;
        a[16] = 255;
    }

    if s.cosy_wind == 0 {
        a[17] = 48
            | (s.right_left_right_wind & 1)
            | (s.left_left_right_wind & 1) << 1
            | (s.right_up_down_wind & 1) << 2
            | (s.left_up_down_wind & 1) << 3;
    } else if s.cosy_wind < 10 {
        a[17] = (s.cosy_wind + 16) as u8;
    } else {
        a[17] = (s.cosy_wind + 22) as u8;
    }

    a[18] = (3 & s.cosy_sleep_mode) | s.alm_sleep << 2 | s.power_save << 3
        | s.farce_wind << 4 | s.strong << 5 | s.energy_save << 6 | s.body_sense << 7;

    let chg_comfort_sleep = if s.cosy_sleep_mode > 0 { 1u8 } else { 0 };
    a[19] = s.wisdom_eye | s.chg_of_air << 1 | s.diy_func << 2 | s.elec_heat << 3
        | s.elec_heat_forced << 4 | s.clean_up_func << 5 | chg_comfort_sleep << 6
        | s.eco_func << 7;

    a[20] = s.sleep_func_state | s.turbo_func_state << 1 | s.temp_mode_switch << 2
        | s.against_cool << 3 | s.night_light << 4 | (s.pmv << 5)
        | s.dust_flow << 6 | s.clean_fan_run_time << 7;

    for i in 0..5 {
        let lo = check_temp_val(s.sleep_temps[2 * i]) - 17;
        let hi = check_temp_val(s.sleep_temps[2 * i + 1]) - 17;
        a[21 + i] = (lo | hi << 4) as u8;
    }

    for i in 0..8 {
        if is_half(s.sleep_temps[i]) {
            a[26] |= 1 << i;
        }
    }

    a[27] = 0;
    if is_half(s.sleep_temps[8]) { a[27] |= 16; }
    if is_half(s.sleep_temps[9]) { a[27] |= 32; }
    a[27] |= 15 & s.comfort_sleep_time;
    a[27] |= (8 & s.pmv) << 4;
    a[27] |= (1 & s.natural_wind) << 6;

    let c = s.temp_set2 + 1; // round(10*TempSet2 + 0.5) for integer tenths
    a[28] = (7 & s.pmv) << 5 | ((c / 10 - 12) & 31) as u8;

    a[29] = (127 & s.humidity).wrapping_add(128);
    a[30] = (1 & s.down_wind) << 7;
    a[31] = 0;
    a[32] = s.cs_eco;
    a[33] = 0;
    a[34] = s.order;
    a[35] = crc8854(&a[10..35]);
    a[1] = 36;
    a[36] = make_sum(&a[1..36]);

    let mut out = Frame::new();
    out.extend_from_slice(&a).ok()?;
    Some(out)
}

/// Build the 24-byte AC query appliance frame (opcode 0x41).
pub fn build_query_frame(order: u8, sound: u8) -> Frame {
    let mut a = [0u8; 24];
    a[0] = 0xAA;
    a[1] = 23;
    a[2] = DEV_TYPE_AC;
    a[9] = 3;
    a[10] = 65;
    a[11] = (sound & 1) << 6 | 33;
    a[13] = 255;
    a[14] = 3;
    a[15] = 255;
    a[17] = 2;
    a[21] = order;
    a[22] = crc8854(&a[10..22]);
    a[23] = make_sum(&a[1..23]);
    let mut out = Frame::new();
    let _ = out.extend_from_slice(&a);
    out
}

/// Parsed 0xC0 AC status reply — the fields the reference (`midea-ble-go`
/// `parse_status_frame`) decodes. Temperatures are integer tenths °C (26.0 = 260).
#[derive(Clone, Copy)]
pub struct Status {
    pub is_on: bool,
    pub has_fault: bool,
    /// Operating-mode wire code 1..=6 (see [`MODE_AUTO`]..[`MODE_SMART_DRY`]).
    pub mode: u8,
    /// Target temperature, tenths °C.
    pub temp_set: i32,
    /// Fan-speed wire code (40/60/80/100/102).
    pub wind_speed: u8,
    pub swing_ud: bool,
    pub swing_lr: bool,
    /// Indoor ambient, tenths °C. `i32::MIN` when the wire reports it unavailable.
    pub temp_indoor: i32,
    /// Outdoor ambient, tenths °C.
    pub temp_outdoor: i32,
    /// Secondary (eco/sleep) setpoint, tenths °C.
    pub temp_secondary: i32,
    pub eco: bool,
    pub turbo: bool,
    pub elec_heat: bool,
    /// Screen-show state, 0..7.
    pub screen: u8,
    pub water_tank_full: bool,
    /// Raw error code byte (38 = water tank full, see [`Status::water_tank_full`]).
    pub error_code: u8,
}

/// Status-body offsets, relative to `frame[10..]` (opcode-onward) — `body[N]` is
/// `frame[10 + N]`. Same convention as [`super::status`] (midea-local) and the
/// reference appliance.rs.
const S_FLAGS: usize = 1;
const S_MODE_TEMP: usize = 2;
const S_FAN: usize = 3;
const S_SWING: usize = 7;
const S_TURBO: usize = 8;
const S_ECO: usize = 9;
const S_TEMP_INDOOR: usize = 11;
const S_TEMP_OUTDOOR: usize = 12;
const S_TEMP_SECONDARY: usize = 13;
const S_SCREEN: usize = 14;
const S_TEMP_TENTHS: usize = 15;
const S_ERROR: usize = 16;
const S_MIN_LEN: usize = 17;

/// Water-tank-full marker in the error byte.
const WATER_TANK_ERROR: u8 = 38;

impl Status {
    /// Write the one-line status summary (power/mode/target/fan plus the extended
    /// fields) into `w` — what recon logs after a handshake.
    pub fn fmt_to(&self, w: &mut impl core::fmt::Write) -> core::fmt::Result {
        write!(
            w,
            "power={} mode={} target={}.{}°C fan={}",
            if self.is_on { "ON" } else { "OFF" },
            mode_name(self.mode),
            self.temp_set / 10,
            self.temp_set.abs() % 10,
            wind_name(self.wind_speed),
        )?;
        if self.temp_indoor != i32::MIN {
            write!(w, " indoor={}.{}°C", self.temp_indoor / 10, self.temp_indoor.abs() % 10)?;
        }
        if self.temp_outdoor != i32::MIN {
            write!(w, " outdoor={}.{}°C", self.temp_outdoor / 10, self.temp_outdoor.abs() % 10)?;
        }
        if self.temp_secondary != 0 {
            write!(w, " set2={}.{}°C", self.temp_secondary / 10, self.temp_secondary.abs() % 10)?;
        }
        if self.eco { write!(w, " eco")?; }
        if self.turbo { write!(w, " turbo")?; }
        if self.elec_heat { write!(w, " elec_heat")?; }
        if self.water_tank_full { write!(w, " tank_full")?; }
        if self.error_code != 0 { write!(w, " err={}", self.error_code)?; }
        if self.has_fault { write!(w, " FAULT")?; }
        Ok(())
    }
}

/// Decode the indoor-ambient temperature: coarse wire byte (integer °C, the
/// half-degree is truncated) plus a tenths nibble, negated for sub-zero.
fn ambient_indoor(coarse: u8, tenths: u8) -> i32 {
    let int = (coarse as i32 - 50) / 2;
    let t = (tenths & 15).min(9) as i32;
    if int < 0 { int * 10 - t } else { int * 10 + t }
}

/// Decode the outdoor-ambient temperature: coarse wire byte (half-degree
/// resolution, not truncated) plus a tenths nibble.
fn ambient_outdoor(coarse: u8, tenths: u8) -> i32 {
    (coarse as i32 - 50) * 5 + (tenths & 15).min(9) as i32
}

/// Parse a 0xC0 AC status frame (the reference `parse_status_frame`). Verifies
/// the sync byte, declared length + checksum (the shared [`super::status::frame_body`]
/// framing gate), and the opcode before decoding. `None` on a malformed frame.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = super::status::frame_body(t)?; // body: b[N] == frame[10 + N]
    if b.len() < S_MIN_LEN || b[0] != 0xC0 {
        return None;
    }
    let swing = (b[S_SWING] & 0xF0) == 0x30;
    Some(Status {
        is_on: b[S_FLAGS] & 1 != 0,
        has_fault: b[S_FLAGS] & 0x80 != 0,
        mode: (b[S_MODE_TEMP] >> 5) & 7,
        temp_set: (16 + (b[S_MODE_TEMP] & 15)) as i32 * 10
            + if b[S_MODE_TEMP] & 16 != 0 { 5 } else { 0 },
        wind_speed: b[S_FAN],
        swing_ud: swing && b[S_SWING] & 0x0C != 0,
        swing_lr: swing && b[S_SWING] & 0x03 != 0,
        temp_indoor: if b[S_TEMP_INDOOR] == 0xFF {
            i32::MIN
        } else {
            ambient_indoor(b[S_TEMP_INDOOR], b[S_TEMP_TENTHS] & 15)
        },
        temp_outdoor: if b[S_TEMP_OUTDOOR] == 0xFF {
            i32::MIN
        } else {
            ambient_outdoor(b[S_TEMP_OUTDOOR], (b[S_TEMP_TENTHS] >> 4) & 15)
        },
        temp_secondary: (12 + (b[S_TEMP_SECONDARY] & 31)) as i32 * 10
            + if b[S_MODE_TEMP] & 16 != 0 { 5 } else { 0 },
        eco: b[S_ECO] & 0x10 != 0,
        turbo: b[S_TURBO] & 0x20 != 0,
        elec_heat: b[S_ECO] & 0x08 != 0,
        screen: (b[S_SCREEN] & 0x70) >> 4,
        water_tank_full: b[S_ERROR] == WATER_TANK_ERROR,
        error_code: b[S_ERROR],
    })
}
