//! What each peer says it is: controller version and FeatureSet.
//!
//! On a privacy-enabled link where the address is resolvable and the name is
//! behind an encrypted GATT read, `LL_VERSION_IND` and the feature exchange are
//! frequently the only identification either side gives away in the clear. The
//! company identifier names the controller vendor, and the set of feature bits
//! is specific enough to separate stack versions from one another.

use core::fmt::Write;

use super::super::features;
use super::{line, send, u16le, Decoder};

pub(super) struct Identity;

impl Decoder<u8> for Identity {
    fn keys(&self) -> &'static [u8] {
        &[0x08, 0x09, 0x0C, 0x0E, 0x2B, 0x2C]
    }

    fn decode(&self, p: &[u8]) {
        let d = &p[1..];
        match p[0] {
            // LL_FEATURE_REQ / LL_FEATURE_RSP / LL_PERIPHERAL_FEATURE_REQ all
            // carry the same 8-octet FeatureSet.
            0x08 | 0x09 | 0x0E if d.len() >= 8 => features::emit(&d[..8]),
            // LL_FEATURE_EXT_REQ / _RSP carry the same FeatureSet, but the
            // extended form may span more than eight octets; emit the whole
            // payload so bits past the named range still print as bit<n>.
            0x2B | 0x2C if d.len() >= 8 => features::emit(d),
            // LL_VERSION_IND: VersNr(1) CompId(2) SubVersNr(2).
            0x0C if d.len() >= 5 => {
                let mut s = line();
                let cid = u16le(d, 1);
                let _ = write!(
                    s, "version={} (0x{:02X}) company=0x{:04X}",
                    Self::version_name(d[0]), d[0], cid
                );
                if let Some(n) = crate::decoder::company_name(cid) {
                    let _ = write!(s, " ({})", n);
                }
                let _ = write!(s, " subversion=0x{:04X}", u16le(d, 3));
                send(s);
            }
            _ => {}
        }
    }
}

/// The version table the `LL_VERSION_IND` arm reads.
impl Identity {
    /// Core specification version from the `VersNr` field (Assigned Numbers).
    fn version_name(v: u8) -> &'static str {
        match v {
            0 => "1.0b",
            1 => "1.1",
            2 => "1.2",
            3 => "2.0",
            4 => "2.1",
            5 => "3.0",
            6 => "4.0",
            7 => "4.1",
            8 => "4.2",
            9 => "5.0",
            10 => "5.1",
            11 => "5.2",
            12 => "5.3",
            13 => "5.4",
            14 => "6.0",
            _ => "?",
        }
    }
}
