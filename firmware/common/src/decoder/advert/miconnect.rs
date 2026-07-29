//! Xiaomi MiConnect / Xiaomi Interconnect service data — UUIDs 0xFCC0, 0xFC66,
//! 0xFDAA and 0xFD2D, all registered to Xiaomi Inc.
//!
//! These four are the cross-device discovery advertisements a Xiaomi handset,
//! tablet or TV emits so the rest of the account's devices can find it. They are
//! undocumented; the layouts below are reverse-engineered from captured traffic
//! and cross-checked against the plaintext device names the frames carry.
//!
//! Three container shapes appear:
//!
//! * **0xFCC0 / 0xFC66** — `[version][flags][0x01][6-byte id][payload]`. The
//!   id is stable across sightings while the advertising address rotates as an
//!   RPA, so it identifies the handset for as long as it is powered on. 0xFC66's
//!   payload is ciphertext. 0xFCC0's carries the device name in chunks: a
//!   `0x20 | len` header introduces the first (up to 31 bytes, in practice 15),
//!   and a `BC [2+n] 01 [n]` TLV carries the remainder. The split lands
//!   mid-word, and can land mid-character, so the chunks are concatenated as
//!   bytes and decoded as UTF-8 once — "Xiaomi 12 Pro D" + "imensity".
//!
//! * **0xFDAA** — a flags byte followed by nibble-TLVs: one header byte holding
//!   `len` in the high nibble and a type in the low nibble, then `len` bytes of
//!   value. Type 3 is a device-name chunk; the chunks concatenate the same way
//!   ("2932773485的Re" + "dmi K70").
//!
//! * **0xFD2D** — `[version][type][payload]`, payload ciphertext.
//!
//! Every recognised frame reports a stable identifier or a plaintext name under
//! a rotating address, which is the point worth logging.

use core::fmt::Write;

use super::{emit, hexdump, write_hex, LogStr};

/// Longest device name reassembled from chunks. Names on air run to about 25
/// bytes ("Xiaomi 12 Pro Dimensity"); CJK names cost 3 bytes a character.
const NAME_CAP: usize = 96;

/// Xiaomi MiConnect cross-device discovery — service data (UUIDs 0xFCC0,
/// 0xFC66, 0xFDAA, 0xFD2D).
pub(super) struct MiConnect;
impl super::VendorDecoder for MiConnect {
    fn service_uuids(&self) -> &'static [u16] { &[0xFCC0, 0xFC66, 0xFDAA, 0xFD2D] }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        match ctx.key {
            0xFCC0 | 0xFC66 => decode_container(ctx, body),
            0xFDAA => decode_nibble_tlv(ctx, body),
            _ => decode_fd2d(ctx, body),
        }
    }
}

/// `[version][flags][0x01][6-byte id][payload]` (0xFCC0, 0xFC66).
fn decode_container(ctx: &super::DecodeCtx, body: &[u8]) {
    if body.len() < 9 || body[2] != 0x01 {
        hexdump(body, ctx.base, 6);
        return;
    }
    let mut s: LogStr = LogStr::new();
    let _ = write!(s, "    MiConnect 0x{:04X}: v{} flags=0x{:02X} id=", ctx.key, body[0], body[1]);
    write_hex(&mut s, &body[3..9]);
    emit(s);

    let payload = &body[9..];
    if let Some(name) = chunked_name(payload) {
        emit_name(ctx.key, &name);
    }
    hexdump(payload, ctx.base + 9, 6);
}

/// Reassemble a device name from a `0x20 | len` first chunk plus an optional
/// `BC [2+n] 01 [n]` continuation TLV. `None` when neither is present.
fn chunked_name(p: &[u8]) -> Option<heapless::Vec<u8, NAME_CAP>> {
    let mut out: heapless::Vec<u8, NAME_CAP> = heapless::Vec::new();

    // First chunk: scan for a length header whose bytes read as text. Binary
    // bytes preceding it fail the text test, so the first hit is the name.
    let mut i = 0;
    let mut end = 0;
    while i < p.len() {
        let n = (p[i] & 0x1F) as usize;
        if p[i] & 0xE0 == 0x20 && n >= 2 && i + 1 + n <= p.len() && is_text(&p[i + 1..i + 1 + n]) {
            let _ = out.extend_from_slice(&p[i + 1..i + 1 + n]);
            end = i + 1 + n;
            break;
        }
        i += 1;
    }
    if out.is_empty() { return None; }

    // Continuation: `BC [len][0x01][strlen][text]`, where len covers the two
    // bytes after it plus the text.
    let mut j = end;
    while j + 4 <= p.len() {
        let m = p[j + 3] as usize;
        if p[j] == 0xBC && p[j + 1] as usize == m + 2 && p[j + 2] == 0x01 && j + 4 + m <= p.len() {
            let _ = out.extend_from_slice(&p[j + 4..j + 4 + m]);
            break;
        }
        j += 1;
    }
    Some(out)
}

/// A flags byte followed by `[(len << 4) | type][value]` nibble-TLVs, type 3
/// carrying device-name chunks (0xFDAA).
fn decode_nibble_tlv(ctx: &super::DecodeCtx, body: &[u8]) {
    // Walk the whole chain first: it is accepted only if the headers tile the
    // body exactly and at least one name chunk is present. A chain that runs
    // past the end is a different format that happens to share the UUID.
    let mut i = 1;
    let mut has_name = false;
    while i < body.len() {
        if body[i] & 0x0F == 0x03 && body[i] >> 4 != 0 { has_name = true; }
        i += 1 + (body[i] >> 4) as usize;
    }
    if body.is_empty() || i != body.len() || !has_name {
        hexdump(body, ctx.base, 6);
        return;
    }

    let mut name: heapless::Vec<u8, NAME_CAP> = heapless::Vec::new();
    let mut other: LogStr = LogStr::new();
    let _ = write!(other, "    MiConnect 0xFDAA: flags=0x{:02X}", body[0]);
    let mut i = 1;
    while i < body.len() {
        let len = (body[i] >> 4) as usize;
        let typ = body[i] & 0x0F;
        let v = &body[i + 1..i + 1 + len];
        if typ == 0x03 {
            let _ = name.extend_from_slice(v);
        } else if v.is_empty() {
            // A zero-length TLV is a bare flag: the header nibble is the whole
            // message, so it prints without a value.
            let _ = write!(other, " t{:X}", typ);
        } else {
            let _ = write!(other, " t{:X}=", typ);
            write_hex(&mut other, v);
        }
        i += 1 + len;
    }
    emit(other);
    emit_name(0xFDAA, &name);
}

/// `[version][type][payload]`, payload ciphertext (0xFD2D).
fn decode_fd2d(ctx: &super::DecodeCtx, body: &[u8]) {
    if body.len() < 2 {
        hexdump(body, ctx.base, 6);
        return;
    }
    let mut s: LogStr = LogStr::new();
    let _ = write!(s, "    MiConnect 0xFD2D: v{} type=0x{:02X} encrypted len={}",
        body[0], body[1], body.len() - 2);
    emit(s);
    hexdump(&body[2..], ctx.base + 2, 6);
}

/// Emit the reassembled name, printing the part that decodes when the frame was
/// cut off mid-character at the AD-structure length limit.
fn emit_name(uuid: u16, name: &[u8]) {
    let mut s: LogStr = LogStr::new();
    let _ = write!(s, "    MiConnect 0x{:04X}: name=\"", uuid);
    match core::str::from_utf8(name) {
        Ok(n) => { let _ = write!(s, "{}\"", n); }
        Err(e) => {
            let vu = e.valid_up_to();
            if let Ok(n) = core::str::from_utf8(&name[..vu]) {
                let _ = write!(s, "{}...\"", n);
            }
        }
    }
    emit(s);
}

/// Whether `b` reads as printable UTF-8 text. A multi-byte character cut in
/// half by the chunk boundary is accepted — the next chunk carries the rest —
/// but any other decoding error or a control character rejects the run.
fn is_text(b: &[u8]) -> bool {
    let head = match core::str::from_utf8(b) {
        Ok(s) => s,
        Err(e) if e.error_len().is_none() && b.len() - e.valid_up_to() <= 3 => {
            match core::str::from_utf8(&b[..e.valid_up_to()]) {
                Ok(s) => s,
                Err(_) => return false,
            }
        }
        Err(_) => return false,
    };
    !head.is_empty() && head.chars().all(|c| !c.is_control())
}
