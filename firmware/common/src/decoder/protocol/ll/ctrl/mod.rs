//! LL Control PDU decoders, one module per procedure family.
//!
//! Core v5.4 Vol 6 Part B §2.4.2. Each module here exposes a unit struct
//! implementing [`Decoder`] over the control opcode and is reached only through
//! the [`CTRL`] registry. Opcodes are grouped by the procedure they belong to
//! rather than by number, because that is how they arrive: a request and its
//! response share a payload layout, and reading one without the other tells you
//! half of what the peers agreed.
//!
//! `decode` receives the whole control payload — opcode first — so a module
//! claiming several opcodes can switch on it.

// Helpers shared by the group modules. Imported once here so each module keeps
// reaching them as `super::…`.
use super::super::{line, send, u16le, u24le, write_hex_be, write_interval, Decoder};
use super::{ctrl_name, error_name, write_phys};

mod encryption;
mod identity;
mod iso;
mod params;
mod phy;
mod power;
mod procedure;
mod sync;
mod timeline;

/// Registry of control-PDU decoders, scanned in order by
/// [`super::emit_ctrl_params`].
pub static CTRL: &[&dyn Decoder<u8>] = &[
    &timeline::Timeline,
    &identity::Identity,
    &encryption::Encryption,
    &procedure::Procedure,
    &params::Params,
    &phy::Phy,
    &power::Power,
    &iso::Iso,
    &sync::Sync,
];
