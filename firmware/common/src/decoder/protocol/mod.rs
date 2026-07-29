//! Wire-protocol decoders for an established connection.
//!
//! The `advert` tree decodes advertising payloads, keyed by vendor. Everything
//! here decodes the stack a follower sees on a data channel once a connection
//! exists: the Link Layer PDU header and its control opcodes ([`ll`]), and the
//! L2CAP frame plus whichever protocol owns its CID ([`l2cap`]).
//!
//! Each layer prints its own fields and hands the body to the next, so a single
//! captured PDU produces one line per layer that recognised it. Nothing here
//! reads or writes radio state — these functions take bytes and emit log lines,
//! which is what lets the follower run them off its capture path.
//!
//! # Registries
//!
//! Every layer here dispatches the same way: decode a header, read the one field
//! that names the body's owner, then look that key up in a registry of
//! [`Decoder`] implementors. [`ll::ctrl::CTRL`] is keyed by control opcode,
//! [`l2cap::CHANNELS`] by channel identifier. Each implementor is a unit struct
//! declared next to the code that decodes its PDUs, so adding a protocol is one
//! new module plus one registry line.

use core::fmt::Write;

pub mod l2cap;
pub mod ll;

// ── Registry trait ────────────────────────────────────────────────────────────

/// One entry in a protocol registry: the keys it claims, and how to decode a
/// body carrying one of them.
///
/// `Key` is the type of the enclosing layer's dispatch field — a `u16` L2CAP
/// CID, a `u8` LL control opcode. One decoder may claim several keys, and
/// usually does: the request and the response of a procedure share a payload
/// layout, so the pair is one implementor rather than two.
pub trait Decoder<Key: 'static>: Sync {
    /// Every key this decoder claims.
    fn keys(&self) -> &'static [Key];

    /// Print the fields of one body claimed by [`Decoder::keys`].
    ///
    /// Where `body` starts is the enclosing layer's choice, documented on that
    /// layer's registry: L2CAP hands over the frame payload, the Link Layer the
    /// control payload including its opcode.
    fn decode(&self, body: &[u8]);
}

/// The first decoder in `table` claiming `key`.
pub fn lookup<K: PartialEq + 'static>(
    table: &'static [&'static dyn Decoder<K>],
    key: K,
) -> Option<&'static dyn Decoder<K>> {
    table.iter().copied().find(|d| d.keys().contains(&key))
}

// ── Line helpers ──────────────────────────────────────────────────────────────

/// Start an indented parameter line.
///
/// Six spaces: a parameter line belongs to the `Packet[N]` header (level 2, four
/// spaces) above it, so its own fields sit one level deeper at level 3, and the
/// depth of the indent reads as depth in the stack.
pub fn line() -> crate::LogLine {
    let mut s = crate::LogLine::new();
    let _ = s.push_str("      ");
    s
}

/// Finish and queue a line started by [`line`].
pub fn send(mut s: crate::LogLine) {
    crate::terminate_line(&mut s);
    crate::log_send(s);
}

// ── Field helpers ─────────────────────────────────────────────────────────────

/// Read a little-endian u16 at `d[i..i + 2]`.
pub fn u16le(d: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([d[i], d[i + 1]])
}

/// Read a little-endian 24-bit value at `d[i..i + 3]`.
pub fn u24le(d: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([d[i], d[i + 1], d[i + 2], 0])
}

/// Append a time held in 1.25 ms units — connection intervals, transmit windows,
/// L2CAP parameter-update requests — as milliseconds.
pub fn write_interval(s: &mut crate::LogLine, units: u16) {
    let us = units as u32 * 1250;
    let _ = write!(s, "{}.{:02}ms", us / 1000, (us % 1000) / 10);
}

/// Append `data` as an unbroken hex string, capped so one oversized value cannot
/// push the rest of the line out of the buffer.
pub fn write_hex_capped(s: &mut crate::LogLine, data: &[u8], cap: usize) {
    let shown = data.len().min(cap);
    for b in &data[..shown] {
        let _ = write!(s, "{:02X}", b);
    }
    if data.len() > shown {
        let _ = write!(s, "… (+{}B)", data.len() - shown);
    }
}

/// Append a little-endian field as hex, most-significant octet first.
///
/// Keys, nonces and random values travel least-significant octet first but are
/// written down and compared the other way round, so printing them in wire order
/// would make a capture disagree with every other tool showing the same value.
pub fn write_hex_be(s: &mut crate::LogLine, data: &[u8]) {
    for b in data.iter().rev() {
        let _ = write!(s, "{:02X}", b);
    }
}
