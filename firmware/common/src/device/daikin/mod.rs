//! Daikin Madoka (BRC1H) wall controller — passive GATT decode.
//!
//! The BRC1H exposes an "emulated UART over BLE": service `2141e110-…` with a
//! notify characteristic (`2141e111`, controller → app) and a write-without-
//! response characteristic (`2141e112`, app → controller). Layouts are from the
//! blafois/Daikin-Madoka-BRC1H-BLE-Reverse write-up. Everything here is
//! *plaintext* — the only access control is a standard BLE bond, so once the link
//! is up (or when following one passively) the command/response TLVs are readable
//! with no key.
//!
//! This module is decode-only ([`gatt::frame`]): it turns a captured
//! characteristic value into a log line. The UUID names are added to the GATT
//! walk in [`crate::central`]. Active control (writing setters) is a separate,
//! bonding-gated effort and is not implemented here.

pub mod gatt;
