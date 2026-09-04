//! Midea heat-pump water heater (type `CD`) status decode, cross-checked against
//! the manufacturer's Lua `T_0000_CD_3.lua` (`binToModel`). Byte offsets are the
//! status body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `CD` heat-pump-water-heater status.
#[derive(Clone, Copy)]
pub struct Status {
    pub power: bool,
    pub energy_mode: bool,
    pub standard_mode: bool,
    pub compatibilizing_mode: bool,
    pub heat: bool,
    pub dicaryon_heat: bool,
    pub eco: bool,
    /// Target temperature (°C).
    pub ts: u8,
    pub wash_box_temp: u8,
    pub box_top_temp: u8,
    pub box_bottom_temp: u8,
    pub t3: u8,
    pub t4: u8,
    pub compressor_top_temp: u8,
    pub ts_max: u8,
    pub ts_min: u8,
}

/// Status-body offsets (`binToModel` reads up to `body[11]`).
const S_FLAGS: usize = 2; // power bit0, energy bit1, standard bit2, compat bit3,
// heat bit4, dicaryon bit5, eco bit6
const S_TS: usize = 3;
const S_WASH_TEMP: usize = 4;
const S_BOX_TOP: usize = 5;
const S_BOX_BOTTOM: usize = 6;
const S_T3: usize = 7;
const S_T4: usize = 8;
const S_COMPRESSOR_TOP: usize = 9;
const S_TS_MAX: usize = 10;
const S_TS_MIN: usize = 11;
const S_MIN_LEN: usize = 12;

/// Parse the status body per the Lua's `binToModel`.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    let f = b[S_FLAGS];
    Some(Status {
        power: f & 0x01 != 0,
        energy_mode: f & 0x02 != 0,
        standard_mode: f & 0x04 != 0,
        compatibilizing_mode: f & 0x08 != 0,
        heat: f & 0x10 != 0,
        dicaryon_heat: f & 0x20 != 0,
        eco: f & 0x40 != 0,
        ts: b[S_TS],
        wash_box_temp: b[S_WASH_TEMP],
        box_top_temp: b[S_BOX_TOP],
        box_bottom_temp: b[S_BOX_BOTTOM],
        t3: b[S_T3],
        t4: b[S_T4],
        compressor_top_temp: b[S_COMPRESSOR_TOP],
        ts_max: b[S_TS_MAX],
        ts_min: b[S_TS_MIN],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(
        w,
        "power={} ts={}°C",
        if st.power { "ON" } else { "OFF" },
        st.ts,
    );
    if st.energy_mode {
        let _ = write!(w, " energy");
    }
    if st.standard_mode {
        let _ = write!(w, " standard");
    }
    if st.compatibilizing_mode {
        let _ = write!(w, " compat");
    }
    if st.heat {
        let _ = write!(w, " heat");
    }
    if st.dicaryon_heat {
        let _ = write!(w, " dicaryon");
    }
    if st.eco {
        let _ = write!(w, " eco");
    }
    let _ = write!(
        w,
        " wash={} top={} bot={} t3={} t4={} comp={} ts[{}..{}]",
        st.wash_box_temp,
        st.box_top_temp,
        st.box_bottom_temp,
        st.t3,
        st.t4,
        st.compressor_top_temp,
        st.ts_min,
        st.ts_max,
    );
    true
}
