//! Midea electric water heater (type `E2`) status decode, cross-checked against
//! the manufacturer's Lua `T_0000_E2_9.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::{frame::Frame, status};

/// Decoded E2 electric-water-heater status.
#[derive(Clone, Copy)]
pub struct Status {
    pub power: bool,
    pub fast_hot: bool,
    pub heating: bool,
    pub keep_warm: bool,
    pub error_code: u8,
    pub current_temp: u8,
    pub water_level: u8,
    pub heat: bool,
    pub sleep: bool,
    pub protect: bool,
    pub safe: bool,
    pub target_temp: u8,
    pub end_time_hour: u8,
    pub end_time_minute: u8,
}

/// Status-body offsets, relative to `frame[10..]`.
const S_FLAGS: usize = 2; // power bit0, fast-hot bit1, heating bit2, keep-warm bit3
const S_ERROR: usize = 3;
const S_CUR_TEMP: usize = 4;
const S_WATER_LEVEL: usize = 5;
const S_MODE_HEAT: usize = 7; // heat bits 2-3
const S_MODE_SLEEP: usize = 8; // sleep bit4
const S_END_HOUR: usize = 9;
const S_END_MIN: usize = 10;
const S_TARGET: usize = 11;
const S_PROTECT_SAFE: usize = 22; // protect bit1, safe bit2
const S_MIN_LEN: usize = 24;

/// Parse the E2 status body (`binToModel`): power/heating/keep-warm/fast-hot in
/// `body[2]`, temps at `[4]`/`[11]`, error at `[3]`, protect/safe at `[22]`.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    let flags = b[S_FLAGS];
    let ps = b[S_PROTECT_SAFE];
    Some(Status {
        power: flags & 0x01 != 0,
        fast_hot: flags & 0x02 != 0,
        heating: flags & 0x04 != 0,
        keep_warm: flags & 0x08 != 0,
        error_code: b[S_ERROR],
        current_temp: b[S_CUR_TEMP],
        water_level: b[S_WATER_LEVEL],
        heat: b[S_MODE_HEAT] & 0x0C != 0,
        sleep: b[S_MODE_SLEEP] & 0x10 != 0,
        protect: ps & 0x02 != 0,
        safe: ps & 0x04 != 0,
        target_temp: b[S_TARGET],
        end_time_hour: b[S_END_HOUR],
        end_time_minute: b[S_END_MIN],
    })
}

/// Build the status-query appliance frame (the `biz_body` the shared t3
/// transport wraps) for the E2 water heater. From the app's `T_0000_E2_9.lua`
/// (`jsonToData`: query body `[0x01, 0x01]`, `BYTE_QUERYL_REQUEST = 0x03`,
/// `getTotalMsg`): `AA [len=13] E2 [6×00] 03 01 01 00 [makeSum]`.
pub fn build_query() -> Frame {
    let mut f = Frame::new();
    let _ = f.resize(14, 0);
    f[0] = 0xAA; // BYTE_PROTOCOL_HEAD
    f[1] = 13; // msgLength = body(2) + BYTE_PROTOCOL_LENGTH(10) + 1
    f[2] = 0xE2; // BYTE_DEVICE_TYPE
    f[9] = 0x03; // BYTE_QUERYL_REQUEST
    f[10] = 0x01; // body[0]
    f[11] = 0x01; // body[1]
    // f[12] = 0x00 reserved — getTotalMsg zero-fills the tail.
    let sum = f[1..=12].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    f[13] = 0u8.wrapping_sub(sum); // makeSum = 256 − Σ(1..12)
    f
}

/// Decode the E2 status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(
        w,
        "power={} temp={}°C tgt={}°C",
        if st.power { "ON" } else { "OFF" },
        st.current_temp,
        st.target_temp,
    );
    if st.fast_hot {
        let _ = write!(w, " fast_hot");
    }
    if st.heating {
        let _ = write!(w, " heating");
    }
    if st.keep_warm {
        let _ = write!(w, " keep_warm");
    }
    if st.heat {
        let _ = write!(w, " heat");
    }
    if st.sleep {
        let _ = write!(w, " sleep");
    }
    if st.protect {
        let _ = write!(w, " protect");
    }
    if st.safe {
        let _ = write!(w, " safe");
    }
    if st.water_level != 0 {
        let _ = write!(w, " water_lvl={}", st.water_level);
    }
    if st.error_code != 0 {
        let _ = write!(w, " err={}", st.error_code);
    }
    if st.end_time_hour != 0 || st.end_time_minute != 0 {
        let _ = write!(w, " end={}:{:02}", st.end_time_hour, st.end_time_minute);
    }
    true
}
