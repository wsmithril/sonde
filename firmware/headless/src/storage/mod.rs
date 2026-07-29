//! SD-card storage for the headless build: a raw append log with a run index,
//! written as PCAP (sniff, conn-follow) or text (gatt). The host `sd_extract.py`
//! slices the card into per-run files.

pub mod fat;
pub mod pcap;
pub mod ring;
pub mod runidx;
pub mod sd;
