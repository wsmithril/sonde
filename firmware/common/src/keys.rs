//! Compiled-in identity keys for resolving rotating BLE identities.
//!
//! EMPTY by default. Populate only for authorized analysis of devices whose keys
//! you legitimately hold — your own devices, or a sanctioned engagement. Resolving
//! third parties' rotating addresses defeats a privacy mechanism, so this is
//! deliberately off unless you build with `--features resolve-identities` and add
//! keys here.
//!
//! Keys are 16 bytes, most-significant-octet first (as printed: an IRK shown as
//! `0102…0F10` is `[0x01, 0x02, …, 0x0F, 0x10]`). If your source gives keys
//! little-endian (HCI byte order), reverse them before pasting.

/// Identity Resolving Keys for RPA resolution (#8): `(irk, label)`. A `rand-rpa`
/// address whose hash matches `ah(irk, prand)` is logged with `label`.
pub const IRKS: &[([u8; 16], &str)] = &[
    // ([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    //   0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F], "my-phone"),
];

/// Set Identity Resolving Keys for CSIP set correlation (#9): `(sirk, label)`. An
/// RSI whose hash matches `ah(sirk, prand)` marks a member of that coordinated
/// set (e.g. left/right earbuds), logged with `label`.
pub const SIRKS: &[([u8; 16], &str)] = &[
    // ([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    //   0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F], "my-earbuds-set"),
];
