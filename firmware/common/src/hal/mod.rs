//! Primitives shared by more than one mode.
//!
//! The capture modes ([`crate::mode`]) all drive the one nRF52840 RADIO and share
//! a handful of low-level building blocks. Those live here, grouped by concern
//! rather than duplicated per mode:
//!
//! * [`radio`] — RADIO config and control (access-address / CRC constants, the
//!   disable guard, hardware-scheduled RXEN, packet layout, per-standard setup).
//! * [`csa2`] — Bluetooth Channel Selection Algorithm #2.
//! * [`hash`] — the shared non-cryptographic fingerprint hash.
//! * [`crypto`] — AES-CCM / RPA resolution and related cryptographic helpers.

pub mod crypto;
pub mod csa2;
pub mod hash;
pub mod radio;
