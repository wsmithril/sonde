//! Midea (type `ED`) status decode, cross-checked against the manufacturer's
//! Lua `T_0000_ED_*.lua` (property-byte decoder). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `ED` status — one field per Lua variable.
#[derive(Clone, Copy)]
pub struct Status {
    pub byte12: u8,
    pub byte13: u8,
    pub byte14: u8,
    pub byte15: u8,
    pub heat_temp: u8,
    pub cool_temp: u8,
    pub byte25: u8,
    pub life1: u8,
    pub life2: u8,
    pub life3: u8,
    pub life4: u8,
    pub life5: u8,
    pub error_code: u8,
    pub water_litre: u16,
    pub filter1: u16,
    pub filter2: u16,
    pub filter3: u16,
    pub filter4: u16,
    pub filter5: u16,
    pub in_t_s_d: u16,
    pub out_t_s_d: u16,
}

/// Status-body minimum length (the highest byte the decoder reads).
const S_MIN_LEN: usize = 40;

/// Parse the status body per the Lua's byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        byte12: b[2],
        byte13: b[3],
        byte14: b[4],
        byte15: b[5],
        heat_temp: b[10],
        cool_temp: b[11],
        byte25: b[15],
        life1: b[16],
        life2: b[17],
        life3: b[18],
        life4: b[19],
        life5: b[20],
        error_code: b[13],
        water_litre: ((b[8] as u16) << 8),
        filter1: ((b[26] as u16) << 8),
        filter2: ((b[28] as u16) << 8),
        filter3: ((b[30] as u16) << 8),
        filter4: ((b[32] as u16) << 8),
        filter5: ((b[34] as u16) << 8),
        in_t_s_d: ((b[37] as u16) << 8),
        out_t_s_d: ((b[39] as u16) << 8),
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "ED status");
    let _ = write!(w, " byte12={}", st.byte12);
    let _ = write!(w, " byte13={}", st.byte13);
    let _ = write!(w, " byte14={}", st.byte14);
    let _ = write!(w, " byte15={}", st.byte15);
    let _ = write!(w, " heat_temp={}", st.heat_temp);
    let _ = write!(w, " cool_temp={}", st.cool_temp);
    let _ = write!(w, " byte25={}", st.byte25);
    let _ = write!(w, " life1={}", st.life1);
    let _ = write!(w, " life2={}", st.life2);
    let _ = write!(w, " life3={}", st.life3);
    let _ = write!(w, " life4={}", st.life4);
    let _ = write!(w, " life5={}", st.life5);
    let _ = write!(w, " error_code={}", st.error_code);
    let _ = write!(w, " water_litre={}", st.water_litre);
    let _ = write!(w, " filter1={}", st.filter1);
    let _ = write!(w, " filter2={}", st.filter2);
    let _ = write!(w, " filter3={}", st.filter3);
    let _ = write!(w, " filter4={}", st.filter4);
    let _ = write!(w, " filter5={}", st.filter5);
    let _ = write!(w, " in_t_s_d={}", st.in_t_s_d);
    let _ = write!(w, " out_t_s_d={}", st.out_t_s_d);
    true
}
