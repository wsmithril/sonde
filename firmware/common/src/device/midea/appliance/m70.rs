//! Midea (type `70`) status decode, cross-checked against the manufacturer's Lua
//! `T_0000_70_*.lua` (`binToModel`, paramTable form). Byte offsets are the status
//! body (`body[N] = frame[10 + N]`, same convention as the AC codec).

use crate::device::midea::status;

/// Decoded `70` status — one `u8` per Lua field.
#[derive(Clone, Copy)]
pub struct Status {
    pub sub_cmd: u8,
    pub box1_type: u8,
    pub box1_status: u8,
    pub box1_add_time_year: u8,
    pub box1_add_time_month: u8,
    pub box1_add_time_day: u8,
    pub box1_add_time_hour: u8,
    pub box1_add_time_minute: u8,
    pub box1_add_time_second: u8,
    pub box1_clean_time_year: u8,
    pub box1_clean_time_month: u8,
    pub box1_clean_time_day: u8,
    pub box1_clean_time_hour: u8,
    pub box1_clean_time_minute: u8,
    pub box1_clean_time_second: u8,
    pub box2_type: u8,
    pub box2_status: u8,
    pub box2_add_time_year: u8,
    pub box2_add_time_month: u8,
    pub box2_add_time_day: u8,
    pub box2_add_time_hour: u8,
    pub box2_add_time_minute: u8,
    pub box2_add_time_second: u8,
    pub box2_clean_time_year: u8,
    pub box2_clean_time_month: u8,
    pub box2_clean_time_day: u8,
    pub box2_clean_time_hour: u8,
    pub box2_clean_time_minute: u8,
    pub box2_clean_time_second: u8,
    pub box3_type: u8,
    pub box3_status: u8,
    pub box3_add_time_year: u8,
    pub box3_add_time_month: u8,
    pub box3_add_time_day: u8,
    pub box3_add_time_hour: u8,
    pub box3_add_time_minute: u8,
    pub box3_add_time_second: u8,
    pub box3_clean_time_year: u8,
    pub box3_clean_time_month: u8,
    pub box3_clean_time_day: u8,
    pub box3_clean_time_hour: u8,
    pub box3_clean_time_minute: u8,
    pub box3_clean_time_second: u8,
    pub box4_type: u8,
    pub box4_status: u8,
    pub box4_add_time_year: u8,
    pub box4_add_time_month: u8,
    pub box4_add_time_day: u8,
    pub box4_add_time_hour: u8,
    pub box4_add_time_minute: u8,
    pub box4_add_time_second: u8,
    pub box4_clean_time_year: u8,
    pub box4_clean_time_month: u8,
    pub box4_clean_time_day: u8,
    pub box4_clean_time_hour: u8,
    pub box4_clean_time_minute: u8,
    pub box4_clean_time_second: u8,
    pub box5_type: u8,
    pub box5_status: u8,
    pub box5_add_time_year: u8,
    pub box5_add_time_month: u8,
    pub box5_add_time_day: u8,
    pub box5_add_time_hour: u8,
    pub box5_add_time_minute: u8,
    pub box5_add_time_second: u8,
    pub box5_clean_time_year: u8,
    pub box5_clean_time_month: u8,
    pub box5_clean_time_day: u8,
    pub box5_clean_time_hour: u8,
    pub box5_clean_time_minute: u8,
    pub box5_clean_time_second: u8,
    pub box6_type: u8,
    pub box6_status: u8,
    pub box6_add_time_year: u8,
    pub box6_add_time_month: u8,
    pub box6_add_time_day: u8,
    pub box6_add_time_hour: u8,
    pub box6_add_time_minute: u8,
    pub box6_add_time_second: u8,
    pub box6_clean_time_year: u8,
    pub box6_clean_time_month: u8,
    pub box6_clean_time_day: u8,
    pub box6_clean_time_hour: u8,
    pub box6_clean_time_minute: u8,
    pub box6_clean_time_second: u8,
    pub box7_type: u8,
    pub box7_status: u8,
    pub box7_add_time_year: u8,
    pub box7_add_time_month: u8,
    pub box7_add_time_day: u8,
    pub box7_add_time_hour: u8,
    pub box7_add_time_minute: u8,
    pub box7_add_time_second: u8,
    pub box7_clean_time_year: u8,
    pub box7_clean_time_month: u8,
    pub box7_clean_time_day: u8,
    pub box7_clean_time_hour: u8,
    pub box7_clean_time_minute: u8,
    pub box7_clean_time_second: u8,
    pub box8_type: u8,
    pub box8_status: u8,
    pub box8_add_time_year: u8,
    pub box8_add_time_month: u8,
    pub box8_add_time_day: u8,
    pub box8_add_time_hour: u8,
    pub box8_add_time_minute: u8,
    pub box8_add_time_second: u8,
    pub box8_clean_time_year: u8,
    pub box8_clean_time_month: u8,
    pub box8_clean_time_day: u8,
    pub box8_clean_time_hour: u8,
    pub box8_clean_time_minute: u8,
    pub box8_clean_time_second: u8,
    pub control_result: u8,
}

/// Status-body minimum length (the highest byte `binToModel` reads).
const S_MIN_LEN: usize = 113;

/// Parse the status body per the Lua's `binToModel` byte reads.
pub fn parse_status_frame(t: &[u8]) -> Option<Status> {
    let b = status::frame_body(t)?;
    if b.len() < S_MIN_LEN {
        return None;
    }
    Some(Status {
        sub_cmd: b[0],
        box1_type: b[1],
        box1_status: b[2],
        box1_add_time_year: b[3],
        box1_add_time_month: b[4],
        box1_add_time_day: b[5],
        box1_add_time_hour: b[6],
        box1_add_time_minute: b[7],
        box1_add_time_second: b[8],
        box1_clean_time_year: b[9],
        box1_clean_time_month: b[10],
        box1_clean_time_day: b[11],
        box1_clean_time_hour: b[12],
        box1_clean_time_minute: b[13],
        box1_clean_time_second: b[14],
        box2_type: b[15],
        box2_status: b[16],
        box2_add_time_year: b[17],
        box2_add_time_month: b[18],
        box2_add_time_day: b[19],
        box2_add_time_hour: b[20],
        box2_add_time_minute: b[21],
        box2_add_time_second: b[22],
        box2_clean_time_year: b[23],
        box2_clean_time_month: b[24],
        box2_clean_time_day: b[25],
        box2_clean_time_hour: b[26],
        box2_clean_time_minute: b[27],
        box2_clean_time_second: b[28],
        box3_type: b[29],
        box3_status: b[30],
        box3_add_time_year: b[31],
        box3_add_time_month: b[32],
        box3_add_time_day: b[33],
        box3_add_time_hour: b[34],
        box3_add_time_minute: b[35],
        box3_add_time_second: b[36],
        box3_clean_time_year: b[37],
        box3_clean_time_month: b[38],
        box3_clean_time_day: b[39],
        box3_clean_time_hour: b[40],
        box3_clean_time_minute: b[41],
        box3_clean_time_second: b[42],
        box4_type: b[43],
        box4_status: b[44],
        box4_add_time_year: b[45],
        box4_add_time_month: b[46],
        box4_add_time_day: b[47],
        box4_add_time_hour: b[48],
        box4_add_time_minute: b[49],
        box4_add_time_second: b[50],
        box4_clean_time_year: b[51],
        box4_clean_time_month: b[52],
        box4_clean_time_day: b[53],
        box4_clean_time_hour: b[54],
        box4_clean_time_minute: b[55],
        box4_clean_time_second: b[56],
        box5_type: b[57],
        box5_status: b[58],
        box5_add_time_year: b[59],
        box5_add_time_month: b[60],
        box5_add_time_day: b[61],
        box5_add_time_hour: b[62],
        box5_add_time_minute: b[63],
        box5_add_time_second: b[64],
        box5_clean_time_year: b[65],
        box5_clean_time_month: b[66],
        box5_clean_time_day: b[67],
        box5_clean_time_hour: b[68],
        box5_clean_time_minute: b[69],
        box5_clean_time_second: b[70],
        box6_type: b[71],
        box6_status: b[72],
        box6_add_time_year: b[73],
        box6_add_time_month: b[74],
        box6_add_time_day: b[75],
        box6_add_time_hour: b[76],
        box6_add_time_minute: b[77],
        box6_add_time_second: b[78],
        box6_clean_time_year: b[79],
        box6_clean_time_month: b[80],
        box6_clean_time_day: b[81],
        box6_clean_time_hour: b[82],
        box6_clean_time_minute: b[83],
        box6_clean_time_second: b[84],
        box7_type: b[85],
        box7_status: b[86],
        box7_add_time_year: b[87],
        box7_add_time_month: b[88],
        box7_add_time_day: b[89],
        box7_add_time_hour: b[90],
        box7_add_time_minute: b[91],
        box7_add_time_second: b[92],
        box7_clean_time_year: b[93],
        box7_clean_time_month: b[94],
        box7_clean_time_day: b[95],
        box7_clean_time_hour: b[96],
        box7_clean_time_minute: b[97],
        box7_clean_time_second: b[98],
        box8_type: b[99],
        box8_status: b[100],
        box8_add_time_year: b[101],
        box8_add_time_month: b[102],
        box8_add_time_day: b[103],
        box8_add_time_hour: b[104],
        box8_add_time_minute: b[105],
        box8_add_time_second: b[106],
        box8_clean_time_year: b[107],
        box8_clean_time_month: b[108],
        box8_clean_time_day: b[109],
        box8_clean_time_hour: b[110],
        box8_clean_time_minute: b[111],
        box8_clean_time_second: b[112],
        control_result: b[1],
    })
}

/// Decode the status reply and write the one-line summary.
pub fn write_status(t: &[u8], w: &mut impl core::fmt::Write) -> bool {
    let Some(st) = parse_status_frame(t) else {
        return false;
    };
    let _ = write!(w, "70 status");
    let _ = write!(w, " sub_cmd={}", st.sub_cmd);
    let _ = write!(w, " box1_type={}", st.box1_type);
    let _ = write!(w, " box1_status={}", st.box1_status);
    let _ = write!(w, " box1_add_time_year={}", st.box1_add_time_year);
    let _ = write!(w, " box1_add_time_month={}", st.box1_add_time_month);
    let _ = write!(w, " box1_add_time_day={}", st.box1_add_time_day);
    let _ = write!(w, " box1_add_time_hour={}", st.box1_add_time_hour);
    let _ = write!(w, " box1_add_time_minute={}", st.box1_add_time_minute);
    let _ = write!(w, " box1_add_time_second={}", st.box1_add_time_second);
    let _ = write!(w, " box1_clean_time_year={}", st.box1_clean_time_year);
    let _ = write!(w, " box1_clean_time_month={}", st.box1_clean_time_month);
    let _ = write!(w, " box1_clean_time_day={}", st.box1_clean_time_day);
    let _ = write!(w, " box1_clean_time_hour={}", st.box1_clean_time_hour);
    let _ = write!(w, " box1_clean_time_minute={}", st.box1_clean_time_minute);
    let _ = write!(w, " box1_clean_time_second={}", st.box1_clean_time_second);
    let _ = write!(w, " box2_type={}", st.box2_type);
    let _ = write!(w, " box2_status={}", st.box2_status);
    let _ = write!(w, " box2_add_time_year={}", st.box2_add_time_year);
    let _ = write!(w, " box2_add_time_month={}", st.box2_add_time_month);
    let _ = write!(w, " box2_add_time_day={}", st.box2_add_time_day);
    let _ = write!(w, " box2_add_time_hour={}", st.box2_add_time_hour);
    let _ = write!(w, " box2_add_time_minute={}", st.box2_add_time_minute);
    let _ = write!(w, " box2_add_time_second={}", st.box2_add_time_second);
    let _ = write!(w, " box2_clean_time_year={}", st.box2_clean_time_year);
    let _ = write!(w, " box2_clean_time_month={}", st.box2_clean_time_month);
    let _ = write!(w, " box2_clean_time_day={}", st.box2_clean_time_day);
    let _ = write!(w, " box2_clean_time_hour={}", st.box2_clean_time_hour);
    let _ = write!(w, " box2_clean_time_minute={}", st.box2_clean_time_minute);
    let _ = write!(w, " box2_clean_time_second={}", st.box2_clean_time_second);
    let _ = write!(w, " box3_type={}", st.box3_type);
    let _ = write!(w, " box3_status={}", st.box3_status);
    let _ = write!(w, " box3_add_time_year={}", st.box3_add_time_year);
    let _ = write!(w, " box3_add_time_month={}", st.box3_add_time_month);
    let _ = write!(w, " box3_add_time_day={}", st.box3_add_time_day);
    let _ = write!(w, " box3_add_time_hour={}", st.box3_add_time_hour);
    let _ = write!(w, " box3_add_time_minute={}", st.box3_add_time_minute);
    let _ = write!(w, " box3_add_time_second={}", st.box3_add_time_second);
    let _ = write!(w, " box3_clean_time_year={}", st.box3_clean_time_year);
    let _ = write!(w, " box3_clean_time_month={}", st.box3_clean_time_month);
    let _ = write!(w, " box3_clean_time_day={}", st.box3_clean_time_day);
    let _ = write!(w, " box3_clean_time_hour={}", st.box3_clean_time_hour);
    let _ = write!(w, " box3_clean_time_minute={}", st.box3_clean_time_minute);
    let _ = write!(w, " box3_clean_time_second={}", st.box3_clean_time_second);
    let _ = write!(w, " box4_type={}", st.box4_type);
    let _ = write!(w, " box4_status={}", st.box4_status);
    let _ = write!(w, " box4_add_time_year={}", st.box4_add_time_year);
    let _ = write!(w, " box4_add_time_month={}", st.box4_add_time_month);
    let _ = write!(w, " box4_add_time_day={}", st.box4_add_time_day);
    let _ = write!(w, " box4_add_time_hour={}", st.box4_add_time_hour);
    let _ = write!(w, " box4_add_time_minute={}", st.box4_add_time_minute);
    let _ = write!(w, " box4_add_time_second={}", st.box4_add_time_second);
    let _ = write!(w, " box4_clean_time_year={}", st.box4_clean_time_year);
    let _ = write!(w, " box4_clean_time_month={}", st.box4_clean_time_month);
    let _ = write!(w, " box4_clean_time_day={}", st.box4_clean_time_day);
    let _ = write!(w, " box4_clean_time_hour={}", st.box4_clean_time_hour);
    let _ = write!(w, " box4_clean_time_minute={}", st.box4_clean_time_minute);
    let _ = write!(w, " box4_clean_time_second={}", st.box4_clean_time_second);
    let _ = write!(w, " box5_type={}", st.box5_type);
    let _ = write!(w, " box5_status={}", st.box5_status);
    let _ = write!(w, " box5_add_time_year={}", st.box5_add_time_year);
    let _ = write!(w, " box5_add_time_month={}", st.box5_add_time_month);
    let _ = write!(w, " box5_add_time_day={}", st.box5_add_time_day);
    let _ = write!(w, " box5_add_time_hour={}", st.box5_add_time_hour);
    let _ = write!(w, " box5_add_time_minute={}", st.box5_add_time_minute);
    let _ = write!(w, " box5_add_time_second={}", st.box5_add_time_second);
    let _ = write!(w, " box5_clean_time_year={}", st.box5_clean_time_year);
    let _ = write!(w, " box5_clean_time_month={}", st.box5_clean_time_month);
    let _ = write!(w, " box5_clean_time_day={}", st.box5_clean_time_day);
    let _ = write!(w, " box5_clean_time_hour={}", st.box5_clean_time_hour);
    let _ = write!(w, " box5_clean_time_minute={}", st.box5_clean_time_minute);
    let _ = write!(w, " box5_clean_time_second={}", st.box5_clean_time_second);
    let _ = write!(w, " box6_type={}", st.box6_type);
    let _ = write!(w, " box6_status={}", st.box6_status);
    let _ = write!(w, " box6_add_time_year={}", st.box6_add_time_year);
    let _ = write!(w, " box6_add_time_month={}", st.box6_add_time_month);
    let _ = write!(w, " box6_add_time_day={}", st.box6_add_time_day);
    let _ = write!(w, " box6_add_time_hour={}", st.box6_add_time_hour);
    let _ = write!(w, " box6_add_time_minute={}", st.box6_add_time_minute);
    let _ = write!(w, " box6_add_time_second={}", st.box6_add_time_second);
    let _ = write!(w, " box6_clean_time_year={}", st.box6_clean_time_year);
    let _ = write!(w, " box6_clean_time_month={}", st.box6_clean_time_month);
    let _ = write!(w, " box6_clean_time_day={}", st.box6_clean_time_day);
    let _ = write!(w, " box6_clean_time_hour={}", st.box6_clean_time_hour);
    let _ = write!(w, " box6_clean_time_minute={}", st.box6_clean_time_minute);
    let _ = write!(w, " box6_clean_time_second={}", st.box6_clean_time_second);
    let _ = write!(w, " box7_type={}", st.box7_type);
    let _ = write!(w, " box7_status={}", st.box7_status);
    let _ = write!(w, " box7_add_time_year={}", st.box7_add_time_year);
    let _ = write!(w, " box7_add_time_month={}", st.box7_add_time_month);
    let _ = write!(w, " box7_add_time_day={}", st.box7_add_time_day);
    let _ = write!(w, " box7_add_time_hour={}", st.box7_add_time_hour);
    let _ = write!(w, " box7_add_time_minute={}", st.box7_add_time_minute);
    let _ = write!(w, " box7_add_time_second={}", st.box7_add_time_second);
    let _ = write!(w, " box7_clean_time_year={}", st.box7_clean_time_year);
    let _ = write!(w, " box7_clean_time_month={}", st.box7_clean_time_month);
    let _ = write!(w, " box7_clean_time_day={}", st.box7_clean_time_day);
    let _ = write!(w, " box7_clean_time_hour={}", st.box7_clean_time_hour);
    let _ = write!(w, " box7_clean_time_minute={}", st.box7_clean_time_minute);
    let _ = write!(w, " box7_clean_time_second={}", st.box7_clean_time_second);
    let _ = write!(w, " box8_type={}", st.box8_type);
    let _ = write!(w, " box8_status={}", st.box8_status);
    let _ = write!(w, " box8_add_time_year={}", st.box8_add_time_year);
    let _ = write!(w, " box8_add_time_month={}", st.box8_add_time_month);
    let _ = write!(w, " box8_add_time_day={}", st.box8_add_time_day);
    let _ = write!(w, " box8_add_time_hour={}", st.box8_add_time_hour);
    let _ = write!(w, " box8_add_time_minute={}", st.box8_add_time_minute);
    let _ = write!(w, " box8_add_time_second={}", st.box8_add_time_second);
    let _ = write!(w, " box8_clean_time_year={}", st.box8_clean_time_year);
    let _ = write!(w, " box8_clean_time_month={}", st.box8_clean_time_month);
    let _ = write!(w, " box8_clean_time_day={}", st.box8_clean_time_day);
    let _ = write!(w, " box8_clean_time_hour={}", st.box8_clean_time_hour);
    let _ = write!(w, " box8_clean_time_minute={}", st.box8_clean_time_minute);
    let _ = write!(w, " box8_clean_time_second={}", st.box8_clean_time_second);
    let _ = write!(w, " control_result={}", st.control_result);
    true
}
