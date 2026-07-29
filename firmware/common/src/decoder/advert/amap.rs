//! Amap (AutoNavi / 高德地图) service data (UUID 0xFDD6).
//!
//! 0xFDD6 is registered to Ministry of Supply, but the frames on air carry the
//! plaintext ASCII tag "gaodeditu" (Gaode Ditu, Amap's Chinese name) alongside a
//! `NBNavi…` local name — an in-car navigation head unit pairing with the Amap
//! app, not the registered member. The tag is printed so the log reflects the
//! device that is actually transmitting.

use core::fmt::Write;

use super::{emit, hexdump, LogStr};

/// Amap in-car navigation — service data (UUID 0xFDD6).
pub(super) struct Amap;
impl super::VendorDecoder for Amap {
    fn service_uuids(&self) -> &'static [u16] { &[0xFDD6] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        match core::str::from_utf8(body) {
            Ok(t) if !t.is_empty() && t.chars().all(|c| !c.is_control()) => {
                let mut s: LogStr = LogStr::new();
                let _ = write!(s, "    Amap 0xFDD6 (squats Ministry of Supply): tag=\"{}\"", t);
                emit(s);
            }
            _ => hexdump(body, ctx.base, 6),
        }
    }
}
