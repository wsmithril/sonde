//! GATT-layer decoding — attribute UUID naming, characteristic value decoding, and
//! vendor transports — split by concern and kept out of [`crate::central`] so the
//! connection code stays about the radio/ATT state machine, not name tables.
//!
//! * [`uuid`]  — 16-bit and 128-bit UUID → name, and [`write_uuid`] for the log.
//! * [`value`] — characteristic value → one readable line ([`known_value`], time,
//!   Android API level).
//! * [`uweave`] — Google BLE-Weave transport header decode.

pub(crate) mod uuid;
pub(crate) mod uweave;
pub(crate) mod value;

pub(crate) use uuid::write_uuid;
pub(crate) use value::{decode_time, format_walltime, known_value, known_value_128};
