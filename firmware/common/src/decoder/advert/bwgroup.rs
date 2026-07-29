//! Bowers & Wilkins manufacturer data (Company ID 0x014F).
//!
//! B&W publishes no spec, but the 13-byte frame its earbuds emit is almost
//! entirely constant and carries a **printable model/product code** in the clear:
//!
//! ```text
//! 0B 00 | 46 50 34 35 30 31 32 | D1 C9 E3 EF
//! ^^ ^^   "F  P  4  5  0  1  2"  ^^^^^^^^^^^ device id (stable per unit)
//! len,type      ASCII product code
//! ```
//!
//! Observed on a B&W "Pi6" earbud (which also advertises Battery 0x180F, Device
//! Information 0x180A and the Qualcomm 0xFD92 service), where the code reads
//! `FP45012`. Byte 2 flips between `F`/`G` between frames — a state or channel
//! marker inside the code region — so the code is reported as-is rather than
//! treated as a fixed identifier.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// B&W Group Ltd. — manufacturer data (Company ID 0x014F).
pub(super) struct BwGroup;
impl super::VendorDecoder for BwGroup {
    fn company_ids(&self) -> &'static [u16] { &[0x014F] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        // Expect the 13-byte layout opening `0B 00`; anything else is unknown.
        if body.len() < 13 || body[0] != 0x0B {
            hexdump(body, ctx.base, 6);
            return;
        }
        let code = &body[2..9];
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    B&W (unofficial): type=0x{:02X}", body[1]);
        if code.iter().all(|&b| b.is_ascii_graphic()) {
            let _ = write!(s, " code=\"");
            for &b in code {
                let _ = write!(s, "{}", b as char);
            }
            let _ = write!(s, "\"");
        } else {
            let _ = write!(s, " code=");
            write_hex(&mut s, code);
        }
        let _ = write!(s, " id=");
        write_hex(&mut s, &body[9..13]);
        emit(s);
    }
}
