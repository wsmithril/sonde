//! Personal carry-device blacklist — devices the user carries (phone, earbuds)
//! that would otherwise dominate every survey and report.
//!
//! Provides the candidate filter ([`is_blacklisted`]) and its build-time config
//! file (`BLACKLIST_CONF`, gitignored `blacklist.conf`). Recon uses the local-name
//! extractor for its built-in local-device filter; callers can use
//! [`is_blacklisted`] for configured exclusions.
#![allow(dead_code)]
//!
//! The **list** lives in a build-time config file, `firmware/common/blacklist.conf`
//! (gitignored — personal, never committed). It is optional: `build.rs` embeds
//! the file's text into the crate as `BLACKLIST_CONF` (`include!` from
//! `OUT_DIR`), and a missing file means an empty blacklist — no devices
//! excluded, build unaffected.
//!
//! Config format — one entry per line:
//! * a bare string is a **substring** of the advertised local-name AD (0x08 or
//!   0x09), e.g.
//!   `WF-1000XM5` (the Sony earbuds advertise `WF-1000XM5` / `LE_WF-1000XM5`);
//! * `addr:AA:BB:CC:DD:EE:FF` matches an **exact** address (stable-address carry
//!   devices such as watches or tags — not usable for privacy-rotating RPAs);
//! * lines starting with `#` are comments.
//!
//! The local-name extractor accepts both the shortened and complete local-name
//! AD types so callers can identify a device from either form.

// Embedded at build time by `build.rs` from `firmware/common/blacklist.conf`
// (empty string when the file is absent).
include!(concat!(env!("OUT_DIR"), "/blacklist_conf.rs"));

/// `true` when the advertised `name` (local-name AD bytes) matches a config entry, or
/// `addr` matches an `addr:` entry. Re-parses the (tiny) config per call.
pub(crate) fn is_blacklisted(name: &[u8], addr: &[u8; 6]) -> bool {
    for line in BLACKLIST_CONF.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(a) = line.strip_prefix("addr:") {
            if addr_matches(a.trim(), addr) {
                return true;
            }
        } else if contains(name, line.as_bytes()) {
            return true;
        }
    }
    false
}

/// The local-name AD bytes (0x08 or 0x09) from an advertising payload, when present.
pub(crate) fn adv_name(ad: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        if matches!(ad[i + 1], 0x08 | 0x09) {
            return Some(&ad[i + 2..i + 1 + flen]);
        }
        i += 1 + flen;
    }
    None
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Compare `"AA:BB:CC:DD:EE:FF"` (from an `addr:` config line) to `addr`.
fn addr_matches(s: &str, addr: &[u8; 6]) -> bool {
    let mut b = [0u8; 6];
    let mut i = 0usize;
    for part in s.split(':') {
        let p = part.as_bytes();
        if i >= 6 || p.len() != 2 {
            return false;
        }
        let (Some(hi), Some(lo)) = (hex(p[0]), hex(p[1])) else {
            return false;
        };
        b[i] = (hi << 4) | lo;
        i += 1;
    }
    i == 6 && b == *addr
}
