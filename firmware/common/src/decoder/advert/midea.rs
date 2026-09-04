//! Midea manufacturer data (Company ID 0x06A8) and service data (UUID 0xFD25).
//!
//! Midea appliances (A/C, fans, kitchen) advertise a manufacturer frame with the
//! layout `[01][SN14][01 03 00 32][MAC6 reversed][00]` (midea-ble-go
//! `docs/protocol.md`): a fixed 0x01 frame byte, a 14-char ASCII short serial,
//! a fixed marker, and — in the full 26-byte form — the appliance's real MAC in
//! reverse. Most units only broadcast the 15-byte `[01][SN14]` short form. The
//! SN and MAC are the HKDF input for the appliance's control-channel root key,
//! so they are the identity worth logging. The `0xFD25` service frame carries
//! binary pairing state with no public layout.

use core::fmt::Write;

use super::{LogStr, emit, hexdump};

/// "Y"/"N" for a non-zero flag byte.
fn y(b: u8) -> &'static str {
    if b != 0 { "Y" } else { "N" }
}

/// Midea — manufacturer data (Company ID 0x06A8) and service data (UUID 0xFD25).
pub(super) struct Midea;
impl super::VendorDecoder for Midea {
    fn company_ids(&self) -> &'static [u16] {
        &[0x06A8]
    }
    fn service_uuids(&self) -> &'static [u16] {
        &[0xFD25]
    }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        if body.is_empty() {
            return;
        }
        match ctx.kind {
            super::FrameKind::Mfg => {
                let mut s: LogStr = LogStr::new();
                let _ = write!(s, "    Midea: type=0x{:02X}", body[0]);
                match body[0] {
                    // Serial block: [01][sn8][type2][last4] — the 14-char ASCII
                    // serial. Short frames stop at the serial; full (>=25B) frames
                    // add a fixed marker and the appliance's real MAC (19..25 rev).
                    0x01 => {
                        let sn = if body.len() >= 15 {
                            &body[1..15]
                        } else {
                            &body[1..]
                        };
                        if !sn.is_empty() && sn.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                            let _ = write!(s, " sn=\"");
                            for &b in sn {
                                let _ = s.push(b as char);
                            }
                            let _ = write!(s, "\"");
                            if body.len() >= 25 && body[15] == 0x01 {
                                let m = &body[19..25];
                                let _ = write!(
                                    s,
                                    " mac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    m[5], m[4], m[3], m[2], m[1], m[0]
                                );
                            }
                            emit(s);
                        } else {
                            emit(s);
                            hexdump(&body[1..], ctx.base + 1, 6);
                        }
                    }
                    // Capability block — the bind/config posture. Layout per the
                    // app's BleAnalyticalUtil.resolvSecondAgreement (body[N] here
                    // is the app's bArr2[N+3], which skips the 0xFF type byte):
                    //   [02][cap][flags][rssi][wifiMac(6)][err][ext]
                    // cap bits:  0 devtype, 1 wifiCfg, 2 bleCfg, 3 bleCfgable,
                    //             4 wifiCfgable, 5 devbind, 6 transport, 7 ota.
                    // flags bits: 0 mesh, 1 meshCfg, 2 fnSet, 3 region,
                    //             4 isBleController (FFA0 no-bind path — ACs),
                    //             5 bleCfgLight, 6 updateRouter, 7 expand.
                    // ext bits (body[12]): 0 wiredCfg, 1 wiredSt, 2 special,
                    //             4 mesh3, 5 aiErr, 6 transportCb, 7 factory.
                    0x02 if body.len() >= 3 => {
                        let c = body[1];
                        let f = body[2];
                        let _ = write!(
                            s,
                            " bletype={} bindable={} ble[cfg={} ok={}] wifi[cfg={} ok={}] devbind={} transport={} ota={} mesh={} controller={}",
                            if c & 0x01 != 0 { "combo" } else { "single" },
                            y(c & 0x08),
                            y(c & 0x04),
                            y(c & 0x08),
                            y(c & 0x02),
                            y(c & 0x10),
                            y(c & 0x20),
                            y(c & 0x40),
                            y(c & 0x80),
                            y(f & 0x01),
                            y(f & 0x10),
                        );
                        if body.len() >= 4 {
                            let _ = write!(s, " rssi={}", body[3]);
                        }
                        if body.len() >= 10 {
                            let m = &body[4..10];
                            let _ = write!(
                                s,
                                " wifiMac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                m[5], m[4], m[3], m[2], m[1], m[0]
                            );
                        }
                        if body.len() >= 13 {
                            let _ = write!(s, " err={} mesh3={}", body[11], y(body[12] & 0x10));
                        }
                        emit(s);
                    }
                    _ => {
                        emit(s);
                        hexdump(&body[1..], ctx.base + 1, 6);
                    }
                }
            }
            super::FrameKind::Service => {
                let mut s: LogStr = LogStr::new();
                let _ = write!(s, "    Midea 0xFD25: len={}", body.len());
                emit(s);
                hexdump(body, ctx.base, 6);
            }
        }
    }
}
