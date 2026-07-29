//! Tentacle Sync (service UUID 0xFDAC) and Zwift (service UUID 0xFC82).
//!
//! Two small, professionally interesting services that otherwise land in the
//! generic hex dump:
//!
//! * **Tentacle Sync 0xFDAC** — timecode sync boxes used on film/video sets. The
//!   service data observed is a short **ASCII device id** (e.g. `CQFMI`), which is
//!   how the Tentacle app labels a unit, so it is printed as text.
//! * **Zwift 0xFC82** — the indoor-cycling platform's companion service, emitted
//!   by trainers/companion apps. Devices carrying it in a capture usually also
//!   advertise Cycling Speed and Cadence (0x1816) or Cycling Power, which is what
//!   actually carries the telemetry; the Zwift frame itself is a short opaque
//!   pairing hint.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Tentacle Sync (0xFDAC) and Zwift (0xFC82) — service data.
pub(super) struct Tentacle;
impl super::VendorDecoder for Tentacle {
    fn service_uuids(&self) -> &'static [u16] { &[0xFDAC, 0xFC82] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        let mut s: LogStr = LogStr::new();
        if ctx.key == 0xFC82 {
            let _ = write!(s, "    Zwift: len={}", body.len());
            if !body.is_empty() {
                let _ = write!(s, " data=");
                write_hex(&mut s, body);
            }
            emit(s);
            return;
        }
        // Tentacle Sync: the body is the printable unit id shown in the app.
        let _ = write!(s, "    Tentacle Sync (timecode): ");
        if !body.is_empty() && body.iter().all(|&b| b.is_ascii_graphic()) {
            let _ = write!(s, "id=\"");
            for &b in body {
                let _ = write!(s, "{}", b as char);
            }
            let _ = write!(s, "\"");
            emit(s);
        } else {
            let _ = write!(s, "len={}", body.len());
            emit(s);
            hexdump(body, ctx.base, 6);
        }
    }
}
