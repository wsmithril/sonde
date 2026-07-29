//! Midea / Hualing appliances.
//!
//! Midea appliances advertise a 0x06A8 manufacturer frame carrying a serial
//! number (decoded in [`crate::decoder::advert`]) and, once connected, expose a
//! control channel over GATT service `0xFFA0` (write `0xFFA1`, notify `0xFFA2`).
//!
//! This module holds the connection-side logic: passive decode of the
//! control-channel framing ([`gatt`]), the three-layer transport builders
//! ([`frame`]), and the AC command/status codec ([`control`]). The crypto layer
//! (rootKey/sessionKey AES-CCM) can grow here as a further submodule. Only
//! [`gatt`] is wired in today; [`frame`]/[`control`] are the encode side, ready
//! but unused.

pub mod control;
pub mod crypto;
pub mod frame;
pub mod gatt;
pub mod handshake;
pub mod rng;
