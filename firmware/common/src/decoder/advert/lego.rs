//! LEGO Powered Up (LWP3) manufacturer data (Company ID 0x0397).
//!
//! Layout per pybricksdev `lwp3/__init__.py` + the LWP3 3.0.00 spec. The
//! 12-byte body (after the 2-byte company ID) is:
//!
//! ```text
//! [0]  button_state  — 0x00 none pressed, 0x01 button held
//! [1]  hub_kind      — hub type (see model_name)
//! [2]  capabilities  — bitmask: bit0=central, bit1=peripheral, bit2=I/O, bit3=remote
//! [3]  last_network  — network ID from last connection (0x00 = none)
//! [4]  status        — bit0=button pressed (duplicate), bit1=advertising-ready
//! [5]  reserved      — typically 0x00
//! [6–11] bd_address  — 6-byte classic Bluetooth address (BE, shown for correlation)
//! ```
//!
//! Hub kind byte values from pybricksdev `HubKind` enum (verified against Powered
//! Up firmware source and community reverse-engineering).

use core::fmt::Write;

use super::{emit, LogStr};

/// LEGO System A/S — manufacturer data (Company ID 0x0397): Powered Up / LWP3 hubs.
pub(super) struct Lego;
impl super::VendorDecoder for Lego {
    fn company_ids(&self) -> &'static [u16] { &[0x0397] }
    fn decode(&self, _ctx: &super::DecodeCtx, body: &[u8]) {
        if body.len() < 6 { return; }

        let button   = body[0] != 0;
        let hub_kind = body[1];
        let caps     = body[2];
        let network  = body[3];
        let status   = body[4];
        // body[5] = reserved

        let mut s: LogStr = LogStr::new();
        let _ = write!(s, "    LEGO {}: btn={} net=0x{:02X} status=0x{:02X}",
            Self::model_name(hub_kind),
            if button { "pressed" } else { "off" },
            network,
            status,
        );

        let _ = write!(s, " cap=[");
        let mut sep = "";
        if caps & 0x01 != 0 { let _ = write!(s, "{}central",   sep); sep = " "; }
        if caps & 0x02 != 0 { let _ = write!(s, "{}peripheral", sep); sep = " "; }
        if caps & 0x04 != 0 { let _ = write!(s, "{}ports",      sep); sep = " "; }
        if caps & 0x08 != 0 { let _ = write!(s, "{}remote",     sep); }
        let _ = write!(s, "]");

        // Remaining 6 bytes: the hub's classic BT address, for correlation with BR/EDR.
        if body.len() >= 12 {
            let a = &body[6..12];
            let _ = write!(s, " bt_addr={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                a[5], a[4], a[3], a[2], a[1], a[0]);
        }
        emit(s);
    }
}

impl Lego {
    fn model_name(t: u8) -> &'static str {
        match t {
            0x00 => "WeDo 2.0 Hub",
            0x20 => "DUPLO Train Hub",
            0x40 => "BOOST Move Hub",
            0x41 => "City Hub (2-port)",
            0x42 => "Handset (remote)",
            0x43 => "Mario Hub",
            0x44 => "Luigi Hub",
            0x45 => "Peach Hub",
            0x80 => "Technic Hub (4-port)",
            0x81 => "SPIKE Prime / MINDSTORMS RI Hub",
            0x83 => "SPIKE Essential Hub",
            0x84 => "Technic Move Hub",
            _    => "Hub (?)",
        }
    }
}
