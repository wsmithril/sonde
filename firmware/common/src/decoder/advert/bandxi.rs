//! Band XI International manufacturer data (Company ID 0x0064).
//!
//! Frames carry nine zero bytes, then an ASCII asset/serial string
//! ("DSPD1SLB1171212B" observed), then a two-byte trailer. The serial is the
//! useful field and is a stable, plaintext identifier.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Band XI International, LLC — manufacturer data (Company ID 0x0064).
pub(super) struct BandXi;
impl super::VendorDecoder for BandXi {
    fn company_ids(&self) -> &'static [u16] { &[0x0064] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        // The serial is the longest printable-ASCII run in the frame.
        let mut best: Option<(usize, usize)> = None;
        let mut start: Option<usize> = None;
        for i in 0..=body.len() {
            let printable = i < body.len() && (0x20..=0x7E).contains(&body[i]);
            match (printable, start) {
                (true, None) => start = Some(i),
                (false, Some(st)) => {
                    if best.is_none_or(|(bs, be)| i - st > be - bs) {
                        best = Some((st, i));
                    }
                    start = None;
                }
                _ => {}
            }
        }
        match best.filter(|&(st, en)| en - st >= 4) {
            Some((st, en)) => {
                let mut s: LogStr = LogStr::new();
                let _ = write!(s, "    Band XI: serial=\"");
                for &b in &body[st..en] { let _ = s.push(b as char); }
                let _ = write!(s, "\"");
                emit(s);
            }
            None => hexdump(body, ctx.base, 6),
        }
    }
}
