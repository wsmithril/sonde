//! Per-boot capture modes for `sonde-headless`. Each file owns one mode's task
//! wrappers and its `spawn` entry; `main`'s `spawn_capture` routes to the chosen
//! one. Output flows mode → `PcapSink`/consumer → `crate::SD_RING` → the SD writer.

pub mod ble_sniff;
pub mod conn_follow;
pub mod gatt;
