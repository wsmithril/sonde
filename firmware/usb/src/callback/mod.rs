//! Per-boot capture modes for `sonde-usb`. Each file owns one mode's peripheral
//! wiring, its `#[task]` wrappers, and a `spawn` entry that `crate::run` routes
//! to. Binary-specific plumbing that can't live in the shared `sonde_common::mode`
//! (QSPI asset window, CDC provisioning) lives here, next to the mode it serves.

pub mod ble_sniff;
pub mod conn_follow;
pub mod gatt;
pub mod midea;
pub mod rssi;
pub mod zigbee;
