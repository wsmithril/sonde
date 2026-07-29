//! L2CAP over an LE-U link, and the protocols on its fixed channels.
//!
//! Core v5.4 Vol 3 Part A. An L2CAP frame is a 4-byte header — payload length
//! and channel identifier — followed by the body, and on LE the CID alone says
//! which protocol owns it. Each of those protocols is a [`Decoder`] in the
//! [`CHANNELS`] registry, keyed by CID: [`att`] on 0x0004, [`le_sig`] on 0x0005,
//! [`smp`] on 0x0006.
//!
//! A frame longer than the Link Layer PDU that carries it continues in later
//! PDUs marked as continuation fragments, so `plen` and the body length
//! disagreeing is normal rather than a decode error.

use super::{lookup, Decoder};

// Helpers shared by the channel protocols. Imported once here so each module
// keeps reaching them as `super::…`.
use super::{line, send, u16le, write_hex_be, write_hex_capped, write_interval};

pub mod att;
pub mod le_sig;
pub mod smp;

/// Registry of channel protocols, keyed by L2CAP CID. `decode` receives the
/// frame body — the bytes after the 4-byte L2CAP header.
pub static CHANNELS: &[&dyn Decoder<u16>] = &[&att::Att, &le_sig::LeSig, &smp::Smp];

/// L2CAP fixed-channel identifiers on an LE-U link.
///
/// Names every fixed CID, including the ones no decoder claims: a frame on
/// 0x0007 or on a dynamic CID is still worth labelling on its header line.
fn cid_name(cid: u16) -> &'static str {
    match cid {
        0x0000 => "null",
        0x0004 => "ATT",
        0x0005 => "LE signalling",
        0x0006 => "SMP",
        0x0007 => "BR/EDR SMP",
        _ => "dynamic",
    }
}

/// Decode an L2CAP frame: the header line, then the CID's protocol.
///
/// `head` prefixes the header line with whatever the caller uses to identify the
/// packet. `p` is the Link Layer payload, starting at the L2CAP length field.
/// Returns whether the body was decoded: `false` for a truncated frame or a CID
/// no [`CHANNELS`] decoder claims, so the caller can dump the undecoded bytes.
pub fn emit(head: &str, p: &[u8]) -> bool {
    if p.len() < 4 {
        crate::ulogf!("{} L2CAP truncated ({} B)\r\n", head, p.len());
        return false;
    }
    let plen = u16le(p, 0);
    let cid = u16le(p, 2);
    let body = &p[4..];
    // `plen` counts only the information payload; a short `body` means the frame
    // continues in the next connection event (llid=01 fragments).
    let frag = if (body.len() as u16) < plen { " (fragmented)" } else { "" };
    crate::ulogf!("{} L2CAP cid=0x{:04X} ({}) plen={}{}\r\n", head, cid, cid_name(cid), plen, frag);
    if body.is_empty() {
        return true;
    }
    match lookup(CHANNELS, cid) {
        Some(d) => {
            d.decode(body);
            true
        }
        None => false,
    }
}
