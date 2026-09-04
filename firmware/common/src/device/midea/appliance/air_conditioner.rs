//! Midea air-conditioner codec: build the 0x40 control / 0x41 query appliance
//! frames and parse the 0xC0 status reply. Byte layout verified against the
//! manufacturer's own protocol Lua (`meijia-decompile/lua/T_0000_AC_22.lua` —
//! `binToModel` / `jsonToData`); the control-encode side traces back to the
//! `midea-ble` reference (`ac/appliance.rs`, a port of midea-ble-go).
//!
//! The appliance frame is the business-layer body: wrap it with
//! [`crate::device::midea::frame::encode_biz`]`(BIZ_TYPE_AC, frame)`, encrypt
//! under the ECDH sessionKey, then `frame::encode_security`(C4, …) and
//! `frame::encode_conn`(T3, …) before writing to GATT `0xFFA1`.
//!
//! Temperatures are integer tenths of a degree (26.0 °C = 260) so the port stays
//! free of floating point. The status decode (`parse_status_frame`) is wired in
//! via `crate::mode::recon::midea`; the control encode side is kept for the full
//! reference capability and is currently unused.
#![allow(dead_code)]

use crate::device::midea::frame::Frame;

/// Business-layer type for AC appliance frames.
pub const BIZ_TYPE_AC: u8 = 32;
const DEV_TYPE_AC: u8 = 0xAC;

// ── Flag sets (the reference's `PowerFlags` / `FeatureFlags`) ────────────────
// Named bit positions so the encode side reads like midea-ble's appliance.rs.
// `PowerFlags` live in `frame[11]`; `FeatureFlags` are logical u32 bits spread
// across `frame[18..21]`, `frame[30]` and `frame[32]` (each wire byte's slice is
// shifted out by the encoder).

/// `frame[11]` power/control flags (midea-ble `PowerFlags`).
pub const RUN_STATUS: u8 = 1 << 0;
pub const IMODE: u8 = 1 << 2;
pub const CHILD_SLEEP: u8 = 1 << 3;
pub const QUICK_CHK: u8 = 1 << 5;
pub const BTN_SOUND: u8 = 1 << 6;

/// Logical feature-flag bit positions (midea-ble `FeatureFlags`), spread across
/// the control frame.
pub const STRONG: u32 = 1 << 2;
pub const ECO_FUNC: u32 = 1 << 10;
pub const ELEC_HEAT: u32 = 1 << 11;
pub const SLEEP_FUNC: u32 = 1 << 16;
pub const TURBO_FUNC: u32 = 1 << 17;
pub const DOWN_WIND: u32 = 1 << 30;
pub const CS_ECO: u32 = 1 << 25;

// ── Typed wire codes (the reference's `Mode` / `FanSpeed` enums) ─────────────

/// AC operating mode — the wire code (1..=6) as a typed value, mirroring the
/// reference `Mode` enum.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Auto = 1,
    Cool = 2,
    Dry = 3,
    Heat = 4,
    Fan = 5,
    SmartDry = 6,
}

impl Mode {
    pub fn from_repr(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Auto),
            2 => Some(Self::Cool),
            3 => Some(Self::Dry),
            4 => Some(Self::Heat),
            5 => Some(Self::Fan),
            6 => Some(Self::SmartDry),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Cool => "cool",
            Self::Dry => "dry",
            Self::Heat => "heat",
            Self::Fan => "fan",
            Self::SmartDry => "smart_dry",
        }
    }
}

/// AC fan speed — the wire code as a typed value. Codes per the manufacturer's
/// Lua (`BYTE_FANSPEED_*`): low `0x28` (40), mid `0x3C` (60), high `0x50` (80),
/// auto `0x66` (102), and mute `0x14` (20).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FanSpeed {
    Low = 40,
    Mid = 60,
    High = 80,
    Mute = 20,
    Auto = 102,
}

impl FanSpeed {
    pub fn from_repr(b: u8) -> Option<Self> {
        match b {
            20 => Some(Self::Mute),
            40 => Some(Self::Low),
            60 => Some(Self::Mid),
            80 => Some(Self::High),
            102 => Some(Self::Auto),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Mid => "mid",
            Self::High => "high",
            Self::Mute => "mute",
            Self::Auto => "auto",
        }
    }
}

/// A wire byte that may or may not be a known variant — `Known` when it matched,
/// `Unknown(raw)` otherwise, so the raw code is never lost.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Parsed<T> {
    Known(T),
    Unknown(u8),
}

impl<T> Parsed<T> {
    pub fn from_repr(byte: u8, decode: impl FnOnce(u8) -> Option<T>) -> Self {
        match decode(byte) {
            Some(v) => Self::Known(v),
            None => Self::Unknown(byte),
        }
    }

    pub fn known(self) -> Option<T> {
        match self {
            Self::Known(v) => Some(v),
            Self::Unknown(_) => None,
        }
    }
}

impl Parsed<Mode> {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Known(m) => m.name(),
            Self::Unknown(_) => "?",
        }
    }
}

impl Parsed<FanSpeed> {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Known(f) => f.name(),
            Self::Unknown(_) => "?",
        }
    }
}

/// Swing / cosy-wind setup from `frame[17]` (the reference `SwingSetup`).
/// Direction bits apply when `cosy_wind == 0`.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct SwingSetup {
    /// Cosy-wind level (0 = disabled — direction bits apply; 1..=9 → +16; else +22).
    pub cosy_wind: u8,
    /// Swing direction bits: bit0 = L/R right unit, bit1 = L/R left unit,
    /// bit2 = U/D right unit, bit3 = U/D left unit.
    pub directions: u8,
}

/// Unpack `frame[17]` into a [`SwingSetup`]: direction bits when the mux nibble
/// is `0x30`, cosy-wind low range (1..=9) at `0x11..=0x19`, else cosy-wind high
/// range at `0x20` and above.
pub fn unpack_swing(byte: u8) -> SwingSetup {
    if (byte & 0xF0) == 0x30 {
        SwingSetup {
            cosy_wind: 0,
            directions: byte & 0x0F,
        }
    } else if (0x11..=0x19).contains(&byte) {
        SwingSetup {
            cosy_wind: byte - 16,
            directions: 0,
        }
    } else if byte >= 0x20 {
        SwingSetup {
            cosy_wind: byte - 22,
            directions: 0,
        }
    } else {
        SwingSetup::default()
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

/// A tiny fluent builder for fixed-layout appliance frames (the reference
/// `FrameBuilder`), over a [`heapless::Vec`] so it stays no_std. Bytes are
/// appended in wire order, so position is implicit — no hand-written offsets.
#[derive(Default)]
pub struct FrameBuilder {
    buf: heapless::Vec<u8, 48>,
}

impl FrameBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one byte.
    pub fn push(mut self, byte: u8) -> Self {
        let _ = self.buf.push(byte);
        self
    }

    /// Append `count` copies of `value` (e.g. reserved zero fields).
    pub fn pad(mut self, value: u8, count: usize) -> Self {
        for _ in 0..count {
            let _ = self.buf.push(value);
        }
        self
    }

    /// Append a byte slice.
    pub fn extend(mut self, bytes: &[u8]) -> Self {
        let _ = self.buf.extend_from_slice(bytes);
        self
    }

    /// Append `checksum(&written[from..])` — a checksum over everything written
    /// from offset `from` up to now.
    pub fn checksum(mut self, from: usize, checksum: impl Fn(&[u8]) -> u8) -> Self {
        let byte = checksum(&self.buf[from..]);
        let _ = self.buf.push(byte);
        self
    }

    /// Finish into a fixed-size array; panics if the built length differs from
    /// `N` (a programming error caught against the golden frames).
    pub fn build<const N: usize>(self) -> [u8; N] {
        assert_eq!(self.buf.len(), N, "frame built to its declared size");
        self.buf.into_array().unwrap_or_else(|_| unreachable!())
    }
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
/// Power / session flags, `frame[11]` (midea-ble `PowerFlags`).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct PowerFlags(pub u8);

impl PowerFlags {
    pub const RUN_STATUS: u8 = 1 << 0;
    pub const IMODE: u8 = 1 << 2;
    pub const CHILD_SLEEP: u8 = 1 << 3;
    pub const QUICK_CHK: u8 = 1 << 5;
    pub const BTN_SOUND: u8 = 1 << 6;

    pub fn contains(&self, f: u8) -> bool {
        self.0 & f != 0
    }
    pub fn set(&mut self, f: u8, on: bool) {
        if on {
            self.0 |= f;
        } else {
            self.0 &= !f;
        }
    }
}

/// Climate fields, `frame[12..14]` + `frame[28]`.
#[derive(Clone, Copy)]
pub struct Climate {
    /// Operating mode.
    pub mode: Mode,
    /// Target temperature, tenths °C.
    pub temperature_target: i32,
    /// Secondary (eco/sleep) setpoint, tenths °C.
    pub temperature_target_secondary: i32,
    /// Fan speed.
    pub fan_speed: FanSpeed,
    /// Temperature-mode switch (`frame[20]` bit 2).
    pub temperature_mode_switch: bool,
}

/// Timer configuration, `frame[14..17]`.
#[derive(Clone, Copy, Default)]
pub struct Timer {
    /// 0 = no timing (the default marker bytes), 1 = absolute-timer path (zeros).
    pub timing_type: u8,
    pub timing_is_valid: bool,
}

/// Feature-flag grab-bag, `frame[18..21]`, `frame[30]`, `frame[32]`.
#[derive(Clone, Copy, Default)]
pub struct Features {
    /// Cosy-sleep mode (0..=3), `frame[18]` bits 0-1; drives the derived
    /// `chgComfortSleep` bit in `frame[19]`.
    pub cosy_sleep_mode: u8,
    pub alm_sleep: bool,
    pub power_save: bool,
    pub farce_wind: bool,
    pub strong: bool,
    pub energy_save: bool,
    pub body_sense: bool,
    pub wisdom_eye: bool,
    pub chg_of_air: bool,
    pub diy_func: bool,
    pub elec_heat: bool,
    pub elec_heat_forced: bool,
    pub clean_up_func: bool,
    pub eco_func: bool,
    pub sleep_func_state: bool,
    pub turbo_func_state: bool,
    pub against_cool: bool,
    pub night_light: bool,
    pub dust_flow: bool,
    pub clean_fan_run_time: bool,
    pub down_wind: bool,
    pub cs_eco: bool,
}

/// Sleep-curve profile, `frame[21..28]`.
#[derive(Clone, Copy)]
pub struct Sleep {
    /// Ten sleep-curve temperatures, tenths °C.
    pub sleep_temps: [i32; 10],
    pub comfort_sleep_time: u8,
    pub natural_wind: bool,
}

impl Default for Sleep {
    fn default() -> Self {
        Self {
            sleep_temps: [260; 10],
            comfort_sleep_time: 10,
            natural_wind: false,
        }
    }
}

/// Sensor-derived fields, `frame[28..30]`.
#[derive(Clone, Copy, Default)]
pub struct Sensors {
    pub humidity: u8,
    /// PMV, bits scattered across `frame[20]`, `frame[27]`, `frame[28]`.
    pub pmv: u8,
}

/// The full appliance state a control frame encodes (midea-ble `AcState`),
/// grouped by domain. Defaults are legal: cool / 26 °C / auto fan, beep on.
#[derive(Clone, Copy)]
pub struct AcState {
    /// Power & session flags (`frame[11]`).
    pub power: PowerFlags,
    /// Mode, target temperature(s), fan.
    pub climate: Climate,
    /// Timer configuration (`frame[14..17]`).
    pub timer: Timer,
    /// Swing & cosy-wind setup (`frame[17]`).
    pub swing: SwingSetup,
    /// Feature-flag grab-bag (`frame[18..21]`, `frame[30]`, `frame[32]`).
    pub features: Features,
    /// Sleep-curve profile (`frame[21..28]`).
    pub sleep: Sleep,
    /// Sensor-derived fields (`frame[28..30]`).
    pub sensors: Sensors,
    /// Frame order counter (`frame[34]`, 1..=255).
    pub order: u8,
}

impl Default for AcState {
    /// A fresh state with legal defaults (cool / 26 °C / auto fan, beep on,
    /// order counter starting at 1).
    fn default() -> Self {
        let mut power = PowerFlags::default();
        power.set(PowerFlags::BTN_SOUND, true);
        power.set(1 << 1, true); // control source (forced by the reference)
        Self {
            power,
            climate: Climate {
                mode: Mode::Cool,
                temperature_target: 260,
                temperature_target_secondary: 260,
                fan_speed: FanSpeed::Auto,
                temperature_mode_switch: false,
            },
            timer: Timer::default(),
            swing: SwingSetup::default(),
            features: Features::default(),
            sleep: Sleep::default(),
            sensors: Sensors::default(),
            order: 1,
        }
    }
}

impl AcState {
    /// Encode this state as a 37-byte control appliance frame (opcode 0x40),
    /// assembled with the [`FrameBuilder`]; each byte is a named field-encoder.
    /// Returns `None` when the target temperature is not a whole or half degree.
    pub fn control_frame(&self) -> Option<Frame> {
        let (on, off, minutes) = self.timers();
        let mode_temp = pack_mode_temperature(self.climate.mode, self.climate.temperature_target)?;
        let secondary = self.temperature_target_secondary_byte();
        let a = FrameBuilder::new()
            .push(0xAA)
            .push(36)
            .push(DEV_TYPE_AC)
            .pad(0, 5)
            .push(2)
            .push(2)
            .push(64)
            .push(self.control_flags())
            .push(mode_temp)
            .push(self.fan_speed_byte())
            .push(on)
            .push(off)
            .push(minutes)
            .push(pack_swing(&self.swing))
            .push(self.features_lo())
            .push(self.features_hi())
            .push(self.features_extra())
            .extend(&self.sleep_curve())
            .push(secondary)
            .push(self.humidity_byte())
            .push(u8::from(self.features.down_wind) << 7)
            .pad(0, 1)
            .push(u8::from(self.features.cs_eco))
            .pad(0, 1)
            .push(self.order)
            .checksum(10, crc8854)
            .checksum(1, make_sum)
            .build::<37>();
        let mut out = Frame::new();
        out.extend_from_slice(&a).ok()?;
        Some(out)
    }

    /// `frame[11]` — the power/session flags.
    fn control_flags(&self) -> u8 {
        self.power.0
    }

    /// `frame[13]` — fan speed + timer-valid bit.
    fn fan_speed_byte(&self) -> u8 {
        (u8::from(self.timer.timing_is_valid) << 7) | (self.climate.fan_speed as u8 & 127)
    }

    /// `frame[14..16]` — timer triplet. The simple controls use no timing
    /// (`timing_type == 0`), which encodes the 127/127/255 marker; the
    /// absolute-timer path is unused (zeros).
    fn timers(&self) -> (u8, u8, u8) {
        if self.timer.timing_type == 1 {
            (0, 0, 0)
        } else {
            (127, 127, 255)
        }
    }

    /// `frame[18]` — feature bits 2-7 + `cosySleepMode` (bits 0-1).
    fn features_lo(&self) -> u8 {
        (3 & self.features.cosy_sleep_mode)
            | u8::from(self.features.alm_sleep) << 2
            | u8::from(self.features.power_save) << 3
            | u8::from(self.features.farce_wind) << 4
            | u8::from(self.features.strong) << 5
            | u8::from(self.features.energy_save) << 6
            | u8::from(self.features.body_sense) << 7
    }

    /// `frame[19]` — feature bits 8-15 with `chgComfortSleep` (bit 6) derived
    /// from `cosy_sleep_mode`.
    fn features_hi(&self) -> u8 {
        u8::from(self.features.wisdom_eye)
            | u8::from(self.features.chg_of_air) << 1
            | u8::from(self.features.diy_func) << 2
            | u8::from(self.features.elec_heat) << 3
            | u8::from(self.features.elec_heat_forced) << 4
            | u8::from(self.features.clean_up_func) << 5
            | u8::from(self.features.cosy_sleep_mode > 0) << 6
            | u8::from(self.features.eco_func) << 7
    }

    /// `frame[20]` — feature bits 16-23 + temperature-mode-switch (bit 2) + pmv
    /// (bits 5-7).
    fn features_extra(&self) -> u8 {
        u8::from(self.features.sleep_func_state)
            | u8::from(self.features.turbo_func_state) << 1
            | u8::from(self.climate.temperature_mode_switch) << 2
            | u8::from(self.features.against_cool) << 3
            | u8::from(self.features.night_light) << 4
            | (self.sensors.pmv << 5)
            | u8::from(self.features.dust_flow) << 6
            | u8::from(self.features.clean_fan_run_time) << 7
    }

    /// `frame[21..28]` — the five sleep-curve temp pairs (nibbles −17) plus the
    /// half-degree flags and the misc byte.
    fn sleep_curve(&self) -> [u8; 7] {
        let pair = |lo: usize, hi: usize| {
            (check_temp_val(self.sleep.sleep_temps[lo]) - 17) as u8
                | ((check_temp_val(self.sleep.sleep_temps[hi]) - 17) << 4) as u8
        };
        let mut half_lo = 0u8; // frame[26]: half-degree flags for temps 0..8
        for (i, t) in self.sleep.sleep_temps.iter().enumerate().take(8) {
            if is_half(*t) {
                half_lo |= 1 << i;
            }
        }
        let mut misc = 0u8; // frame[27]: halves 8/9 + comfort time + pmv + natural wind
        if is_half(self.sleep.sleep_temps[8]) {
            misc |= 16;
        }
        if is_half(self.sleep.sleep_temps[9]) {
            misc |= 32;
        }
        misc |= 15 & self.sleep.comfort_sleep_time;
        misc |= (8 & self.sensors.pmv) << 4;
        misc |= u8::from(self.sleep.natural_wind) << 6;
        [
            pair(0, 1),
            pair(2, 3),
            pair(4, 5),
            pair(6, 7),
            pair(8, 9),
            half_lo,
            misc,
        ]
    }

    /// `frame[28]` — secondary temperature setpoint + PMV (bits 5-7).
    fn temperature_target_secondary_byte(&self) -> u8 {
        let c = self.climate.temperature_target_secondary + 1; // round(10*T + 0.5)
        (7 & self.sensors.pmv) << 5 | ((c / 10 - 12) & 31) as u8
    }

    /// `frame[29]` — humidity, with the high bit always set.
    fn humidity_byte(&self) -> u8 {
        (127 & self.sensors.humidity).wrapping_add(128)
    }
}

/// Pack mode + target temperature into `frame[12]`: mode in bits 5-7,
/// temperature in bits 0-4 (5-bit halfstep). `None` when the temperature is not
/// a whole or half degree within 16..=30 °C.
fn pack_mode_temperature(mode: Mode, temp: i32) -> Option<u8> {
    if !(160..=300).contains(&temp) || !matches!(temp % 10, 0 | 5) {
        return None;
    }
    Some(
        (mode as u8 & 7) << 5 | ((temp / 10 - 16) & 15) as u8 | if temp % 10 == 5 { 16 } else { 0 },
    )
}

/// Pack `frame[17]` from a [`SwingSetup`] — the [`unpack_swing`] inverse.
fn pack_swing(s: &SwingSetup) -> u8 {
    if s.cosy_wind == 0 {
        0x30 | s.directions
    } else if s.cosy_wind < 10 {
        s.cosy_wind.wrapping_add(16)
    } else {
        s.cosy_wind.wrapping_add(22)
    }
}

pub fn build_query_frame(order: u8, sound: u8) -> Frame {
    let a = FrameBuilder::new()
        .push(0xAA)
        .push(23)
        .push(DEV_TYPE_AC)
        .pad(0, 6) // a[3..9] reserved
        .push(3)
        .push(65) // opcode 0x41
        .push((sound & 1) << 6 | 33)
        .push(0)
        .push(255)
        .push(3)
        .push(255)
        .push(0)
        .push(2)
        .pad(0, 3) // a[18..21] reserved
        .push(order)
        .checksum(10, crc8854)
        .checksum(1, make_sum)
        .build::<24>();
    let mut out = Frame::new();
    let _ = out.extend_from_slice(&a);
    out
}

/// Parsed 0xC0 AC status reply — the fields the reference (`midea-ble-go`
/// `parse_status_frame`) decodes. Temperatures are integer tenths °C (26.0 = 260);
/// mode/fan are typed wire codes ([`Parsed`] keeps the raw byte when unknown).
#[derive(Clone, Copy)]
pub struct Status {
    pub is_on: bool,
    pub has_fault: bool,
    /// Operating mode — [`Mode`] when the wire code is known.
    pub mode: Parsed<Mode>,
    /// Target temperature, tenths °C.
    pub temp_set: i32,
    /// Fan speed — [`FanSpeed`] when the wire code is known.
    pub fan_speed: Parsed<FanSpeed>,
    /// Swing / cosy-wind setup.
    pub swing: SwingSetup,
    /// Indoor ambient, tenths °C. `i32::MIN` when the wire reports it unavailable.
    pub temp_indoor: i32,
    /// Outdoor ambient, tenths °C.
    pub temp_outdoor: i32,
    /// Secondary (eco/sleep) setpoint, tenths °C.
    pub temp_secondary: i32,
    pub eco: bool,
    pub turbo: bool,
    pub elec_heat: bool,
    /// Official-Lua fields (beyond the midea-ble port): b[9] bit2 dry, bit5
    /// purifier, bits 3-4 PTC; b[8] bits 0-1 comfortable-sleep; b[10] bit2
    /// kick-quilt, bit3 prevent-cold.
    pub dry: bool,
    pub purifier: bool,
    pub ptc: bool,
    pub comfortable_sleep: u8,
    pub kick_quilt: bool,
    pub prevent_cold: bool,
    /// Screen-show state, 0..7.
    pub screen: u8,
    pub water_tank_full: bool,
    /// Raw error code byte (38 = water tank full, see [`Status::water_tank_full`]).
    pub error_code: u8,
}

/// Status-body offsets, relative to `frame[10..]` (opcode-onward) — `body[N]` is
/// `frame[10 + N]`. Same convention as [`crate::device::midea::status`] (midea-local) and the
/// reference appliance.rs.
const S_FLAGS: usize = 1;
const S_MODE_TEMP: usize = 2;
const S_FAN: usize = 3;
const S_SWING: usize = 7;
const S_TURBO: usize = 8; // strong-wind bit (0x20) per the Lua
const S_ECO: usize = 9;
const S_COMFORT: usize = 10; // kick-quilt / prevent-cold bits
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
            self.mode.name(),
            self.temp_set / 10,
            self.temp_set.abs() % 10,
            self.fan_speed.name(),
        )?;
        // Swing: direction bits when cosy-wind is off, else the cosy level.
        if self.swing.directions != 0 {
            write!(
                w,
                " swing={}{}",
                if self.swing.directions & 0x0C != 0 {
                    "ud"
                } else {
                    ""
                },
                if self.swing.directions & 0x03 != 0 {
                    "lr"
                } else {
                    ""
                },
            )?;
        } else if self.swing.cosy_wind != 0 {
            write!(w, " cosy={}", self.swing.cosy_wind)?;
        }
        if self.temp_indoor != i32::MIN {
            write!(
                w,
                " indoor={}.{}°C",
                self.temp_indoor / 10,
                self.temp_indoor.abs() % 10
            )?;
        }
        if self.temp_outdoor != i32::MIN {
            write!(
                w,
                " outdoor={}.{}°C",
                self.temp_outdoor / 10,
                self.temp_outdoor.abs() % 10
            )?;
        }
        if self.temp_secondary != 0 {
            write!(
                w,
                " set2={}.{}°C",
                self.temp_secondary / 10,
                self.temp_secondary.abs() % 10
            )?;
        }
        if self.eco {
            write!(w, " eco")?;
        }
        if self.turbo {
            write!(w, " turbo")?;
        }
        if self.elec_heat {
            write!(w, " elec_heat")?;
        }
        if self.dry {
            write!(w, " dry")?;
        }
        if self.purifier {
            write!(w, " purifier")?;
        }
        if self.ptc {
            write!(w, " ptc")?;
        }
        if self.kick_quilt {
            write!(w, " kick_quilt")?;
        }
        if self.prevent_cold {
            write!(w, " prevent_cold")?;
        }
        if self.comfortable_sleep != 0 {
            write!(w, " sleep={}", self.comfortable_sleep)?;
        }
        if self.water_tank_full {
            write!(w, " tank_full")?;
        }
        if self.error_code != 0 {
            write!(w, " err={}", self.error_code)?;
        }
        if self.has_fault {
            write!(w, " FAULT")?;
        }
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

/// Decode the outdoor-ambient temperature — the official Lua (`binToModel`)
/// uses the SAME `(b - 50) / 2` scale as indoor; the earlier `* 5` was a
/// midea-ble-go guess. Same tenths-nibble refinement as indoor.
fn ambient_outdoor(coarse: u8, tenths: u8) -> i32 {
    ambient_indoor(coarse, tenths)
}

/// Decode the AC status reply and write the one-line summary — the dispatcher
/// entry used by [`super::write_status`].
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    st.fmt_to(w).is_ok()
}

/// Parse a 0xC0 AC status frame (the reference `parse_status_frame`). Verifies
/// the sync byte, declared length + checksum (the shared [`crate::device::midea::status::frame_body`]
/// framing gate), and the opcode before decoding. `None` on a malformed frame.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = crate::device::midea::status::frame_body(t)?; // body: b[N] == frame[10 + N]
    if b.len() < S_MIN_LEN || b[0] != 0xC0 {
        return None;
    }
    Some(Status {
        is_on: b[S_FLAGS] & 1 != 0,
        has_fault: b[S_FLAGS] & 0x80 != 0,
        mode: Parsed::from_repr((b[S_MODE_TEMP] >> 5) & 7, Mode::from_repr),
        temp_set: (16 + (b[S_MODE_TEMP] & 15)) as i32 * 10
            + if b[S_MODE_TEMP] & 16 != 0 { 5 } else { 0 },
        fan_speed: Parsed::from_repr(b[S_FAN], FanSpeed::from_repr),
        swing: unpack_swing(b[S_SWING]),
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
        turbo: b[S_TURBO] & 0x20 != 0, // official strong-wind bit
        elec_heat: b[S_ECO] & 0x08 != 0,
        dry: b[S_ECO] & 0x04 != 0,
        purifier: b[S_ECO] & 0x20 != 0,
        ptc: b[S_ECO] & 0x18 != 0,
        comfortable_sleep: b[S_TURBO] & 0x03,
        kick_quilt: b[S_COMFORT] & 0x04 != 0,
        prevent_cold: b[S_COMFORT] & 0x08 != 0,
        screen: (b[S_SCREEN] & 0x70) >> 4,
        water_tank_full: b[S_ERROR] == WATER_TANK_ERROR,
        error_code: b[S_ERROR],
    })
}
