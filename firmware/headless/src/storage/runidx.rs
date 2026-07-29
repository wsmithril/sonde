//! Run index: the on-card directory of capture runs.
//!
//! The card is a linear append log. A *run* is one contiguous extent — an hourly
//! sniff PCAP, one followed connection's PCAP, or a GATT text session. The
//! superblock (one 512-byte block at a reserved LBA) records each run's extent so
//! the host `sd_extract.py` can slice the card into files without an on-card
//! filesystem. `len` is re-flushed as a run grows, so a power loss costs only the
//! bytes since the last flush and never corrupts earlier runs.
//!
//! This module is pure logic over an in-memory copy of the superblock; the writer
//! task does the actual block I/O through [`super::sd`].

use heapless::Vec;

/// Reserved LBA holding the superblock. Run data starts at [`DATA_START_LBA`].
pub const SUPERBLOCK_LBA: u32 = 0;
/// One reserved block for the append-only panic log (never rolled into a run).
pub const PANIC_LBA: u32 = 1;
pub const DATA_START_LBA: u32 = 2048; // leave 1 MiB for the superblock/growth
pub const BLOCK: u32 = 512;

const MAGIC: u32 = 0x534E_4452; // "SNDR"
pub const MAX_RUNS: usize = 512;

/// Capture mode a run belongs to (mirrors the boot-mode subset headless captures).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Sniff = 0,
    ConnFollow = 1,
    Gatt = 2,
}

/// Payload kind — PCAP (sniff, conn-follow) or plain text (gatt, status).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Pcap = 0,
    Text = 1,
}

#[derive(Clone, Copy)]
pub struct Run {
    pub mode: u8,
    pub kind: u8,
    pub index: u16,
    pub start_lba: u32,
    pub len_bytes: u32,
    pub finalized: u8,
}

pub struct RunIndex {
    pub runs: Vec<Run, MAX_RUNS>,
    /// Next per-mode file number (`sniff-1`, `sniff-2`, …).
    next_idx: [u16; 3],
    /// First LBA not yet allocated to any run.
    next_lba: u32,
}

impl RunIndex {
    /// A fresh (empty) index for a blank or unreadable card.
    pub fn empty() -> Self {
        Self { runs: Vec::new(), next_idx: [1; 3], next_lba: DATA_START_LBA }
    }

    /// Parse a superblock block; returns [`Self::empty`] if the magic is absent
    /// (blank card) so a first run starts cleanly.
    pub fn decode(block: &[u8; 512]) -> Self {
        if u32::from_le_bytes([block[0], block[1], block[2], block[3]]) != MAGIC {
            return Self::empty();
        }
        let count = u16::from_le_bytes([block[4], block[5]]) as usize;
        let mut idx = Self::empty();
        let mut off = 8;
        for _ in 0..count.min(MAX_RUNS) {
            let r = Run {
                mode: block[off],
                kind: block[off + 1],
                index: u16::from_le_bytes([block[off + 2], block[off + 3]]),
                start_lba: u32::from_le_bytes([
                    block[off + 4], block[off + 5], block[off + 6], block[off + 7],
                ]),
                len_bytes: u32::from_le_bytes([
                    block[off + 8], block[off + 9], block[off + 10], block[off + 11],
                ]),
                finalized: block[off + 12],
            };
            let end = r.start_lba + r.len_bytes.div_ceil(BLOCK);
            idx.next_lba = idx.next_lba.max(end);
            let m = r.mode as usize;
            if m < 3 {
                idx.next_idx[m] = idx.next_idx[m].max(r.index + 1);
            }
            let _ = idx.runs.push(r);
            off += 13;
        }
        idx
    }

    /// Serialize the index into one 512-byte block for the superblock LBA.
    pub fn encode(&self) -> [u8; 512] {
        let mut b = [0u8; 512];
        b[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&(self.runs.len() as u16).to_le_bytes());
        let mut off = 8;
        for r in &self.runs {
            if off + 13 > 512 {
                break;
            }
            b[off] = r.mode;
            b[off + 1] = r.kind;
            b[off + 2..off + 4].copy_from_slice(&r.index.to_le_bytes());
            b[off + 4..off + 8].copy_from_slice(&r.start_lba.to_le_bytes());
            b[off + 8..off + 12].copy_from_slice(&r.len_bytes.to_le_bytes());
            b[off + 12] = r.finalized;
            off += 13;
        }
        b
    }

    /// Close any run left open by a crash, at its last-flushed length.
    pub fn close_unfinalized(&mut self) {
        for r in &mut self.runs {
            r.finalized = 1;
        }
    }

    /// Start a new run, returning its index in `self.runs`. The run begins at the
    /// next free block; `len_bytes` grows as the writer flushes.
    pub fn start(&mut self, mode: Mode, kind: Kind) -> Option<usize> {
        let m = mode as usize;
        let run = Run {
            mode: mode as u8,
            kind: kind as u8,
            index: self.next_idx[m],
            start_lba: self.next_lba,
            len_bytes: 0,
            finalized: 0,
        };
        self.next_idx[m] += 1;
        if self.runs.push(run).is_err() {
            return None;
        }
        Some(self.runs.len() - 1)
    }

    /// Update the growing run's length and, on `final_`, reserve its blocks so the
    /// next run starts after it.
    pub fn set_len(&mut self, run: usize, len: u32, final_: bool) {
        if let Some(r) = self.runs.get_mut(run) {
            r.len_bytes = len;
            if final_ {
                r.finalized = 1;
                self.next_lba = r.start_lba + len.div_ceil(BLOCK);
            }
        }
    }
}
