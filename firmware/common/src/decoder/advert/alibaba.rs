//! Alibaba / Taobao manufacturer data (Company ID 0x01A8).
//!
//! Used by the Taobao / AliGenie app ecosystem (shake-to-pair, IoT onboarding).
//! Each frame carries a leading rotating prefix followed by an ASCII device /
//! pairing identifier (typically 8+ alphanumeric characters). The layout is not
//! published, so we surface the embedded ASCII id and dump the rest.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Taobao / Alibaba — manufacturer data (Company ID 0x01A8).
pub(super) struct Alibaba;
impl super::VendorDecoder for Alibaba {
    fn company_ids(&self) -> &'static [u16] { &[0x01A8] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    Taobao/AliGenie:");
        match longest_ascii_run(body) {
            Some((run, off)) => {
                let _ = write!(s, " id=\"");
                for &b in run { let _ = s.push(b as char); }
                let _ = write!(s, "\" @p{:02X}", ctx.base + off);
            }
            None => { let _ = write!(s, " (no ascii id)"); }
        }
        emit(s);
        hexdump(body, ctx.base, 6);
    }
}

/// Return the longest run of printable ASCII (0x20..=0x7E) at least 4 bytes long,
/// with its start offset within `body`. Alphanumeric-heavy Alibaba ids stand out
/// as the single dominant run; picking the longest avoids stray 1-2 char noise.
fn longest_ascii_run(body: &[u8]) -> Option<(&[u8], usize)> {
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let mut i = 0;
    while i < body.len() {
        if (0x20..=0x7E).contains(&body[i]) {
            let start = i;
            while i < body.len() && (0x20..=0x7E).contains(&body[i]) { i += 1; }
            if i - start > best_len { best_len = i - start; best_start = start; }
        } else {
            i += 1;
        }
    }
    (best_len >= 4).then_some((&body[best_start..best_start + best_len], best_start))
}
