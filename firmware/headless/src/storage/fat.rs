//! Synthetic, read-only FAT32 over the raw capture card.
//!
//! When a host is connected, the MSC layer serves a FAT32 volume that is
//! *computed on demand* — nothing is written to the card. Each finalized run
//! appears as one file whose data blocks are redirected straight to that run's
//! card extent, so the host reads the real PCAP/text bytes with no copy. Only
//! finalized runs are listed, so a run still being appended is never exposed.
//!
//! The exact layout below was validated on macOS (`hdiutil attach`): it mounts as
//! Windows_FAT_32 and lists the files with correct sizes and content. `synth`
//! (metadata) and `locate` (metadata-vs-card routing) are pure, so they can be
//! reasoned about and, if needed, replayed on the host; only the card reads for
//! file-data regions are async and belong to the MSC task.

use heapless::Vec;

use super::runidx::{BLOCK, DATA_START_LBA, PANIC_LBA, Run};

const PART_START: u32 = 2048; // MBR reserves the first 1 MiB, FAT32 convention
const RESERVED: u32 = 32; // reserved sectors before the FATs
const NFATS: u32 = 2;
const ROOT_CLUSTER: u32 = 2;
const MIN_DATA_CLUSTERS: u32 = 65525; // FAT32 lower bound
const MAX_FILES: usize = super::runidx::MAX_RUNS;

/// What a given absolute volume LBA maps to.
pub enum Region {
    /// Synthesize it here (MBR/boot/FSInfo/FAT/root-dir, or zero fill).
    Synthetic,
    /// Read this block from the physical card instead.
    Card(u32),
}

struct FileEnt {
    /// 8.3 name, space-padded (11 bytes: 8 base + 3 ext).
    name: [u8; 11],
    first_cluster: u32,
    n_clusters: u32,
    len: u32,
    card_start_lba: u32,
}

pub struct Fat {
    files: Vec<FileEnt, MAX_FILES>,
    fat_sectors: u32,
    part_total: u32,
}

fn le(out: &mut [u8], v: u32, n: usize) {
    for (i, slot) in out.iter_mut().take(n).enumerate() {
        *slot = (v >> (8 * i)) as u8;
    }
}

/// Build the 8.3 name `<mode>-<index>.<ext>` (e.g. `SNIFF-1 PCP`). PCAP files use
/// the `.PCP` extension because 8.3 allows only three characters — Wireshark opens
/// them by content regardless.
fn short_name(mode: u8, kind: u8, index: u16) -> [u8; 11] {
    let base = match mode {
        0 => b"SNIFF-",
        1 => b"CONN--",
        _ => b"GATT--",
    };
    let ext: &[u8; 3] = if kind == 0 { b"PCP" } else { b"TXT" };
    let mut n = [b' '; 11];
    // base label (6 chars) + up to 2 digits of the index.
    n[..6].copy_from_slice(&base[..6]);
    let mut i = index.min(99);
    if i >= 10 {
        n[6] = b'0' + (i / 10) as u8;
        n[7] = b'0' + (i % 10) as u8;
    } else {
        n[6] = b'0' + i as u8;
        let _ = &mut i;
    }
    n[8..11].copy_from_slice(ext);
    n
}

impl Fat {
    /// Build the volume view from the finalized runs.
    pub fn new(runs: &[Run]) -> Self {
        let mut files: Vec<FileEnt, MAX_FILES> = Vec::new();
        // cluster 2 is the root directory (one cluster; 16 entries fit, which is
        // MAX_FILES-limited by the caller). Files start at cluster 3.
        let mut cluster = ROOT_CLUSTER + 1;
        // The dedicated panic block is always exposed as PANIC.TXT — the whole
        // 512-byte block (2-byte length header included) so a host can read crash
        // reports without pulling the card.
        let _ = files.push(FileEnt {
            name: *b"PANIC   TXT",
            first_cluster: cluster,
            n_clusters: 1,
            len: BLOCK,
            card_start_lba: PANIC_LBA,
        });
        cluster += 1;
        for r in runs {
            if r.finalized == 0 || r.len_bytes == 0 {
                continue;
            }
            let n_clusters = r.len_bytes.div_ceil(BLOCK).max(1);
            if files
                .push(FileEnt {
                    name: short_name(r.mode, r.kind, r.index),
                    first_cluster: cluster,
                    n_clusters,
                    len: r.len_bytes,
                    card_start_lba: r.start_lba,
                })
                .is_err()
            {
                break;
            }
            cluster += n_clusters;
        }
        let top = cluster; // first free cluster
        let data_clusters = MIN_DATA_CLUSTERS.max(top) + 16;
        let fat_sectors = (data_clusters + 2) * 4;
        let fat_sectors = fat_sectors.div_ceil(BLOCK);
        let part_total = RESERVED + NFATS * fat_sectors + data_clusters;
        Self { files, fat_sectors, part_total }
    }

    fn data_start_rel(&self) -> u32 {
        RESERVED + NFATS * self.fat_sectors
    }

    /// Reported LUN size in 512-byte blocks (for READ CAPACITY).
    pub fn total_blocks(&self) -> u32 {
        PART_START + self.part_total
    }

    /// Absolute LBA of a data cluster.
    fn cluster_lba(&self, cluster: u32) -> u32 {
        PART_START + self.data_start_rel() + (cluster - ROOT_CLUSTER)
    }

    /// Which file (if any) owns `cluster`, and the block offset within it.
    fn file_at(&self, cluster: u32) -> Option<(&FileEnt, u32)> {
        for f in &self.files {
            if cluster >= f.first_cluster && cluster < f.first_cluster + f.n_clusters {
                return Some((f, cluster - f.first_cluster));
            }
        }
        None
    }

    /// Route an absolute volume LBA to synthetic metadata or a physical card block.
    pub fn locate(&self, lba: u32) -> Region {
        let data0 = self.cluster_lba(ROOT_CLUSTER); // root dir = cluster 2
        if lba < data0 {
            return Region::Synthetic; // MBR + boot/FSInfo/backup + FATs + (pre-root)
        }
        let cluster = ROOT_CLUSTER + (lba - data0);
        if cluster == ROOT_CLUSTER {
            return Region::Synthetic; // root directory
        }
        match self.file_at(cluster) {
            Some((f, off)) => Region::Card(f.card_start_lba + off),
            None => Region::Synthetic, // free space → zeros
        }
    }

    /// Fill `out` with the synthetic block for `lba` (zeros for unused regions).
    pub fn synth(&self, lba: u32, out: &mut [u8; 512]) {
        out.fill(0);
        if lba == 0 {
            self.mbr(out);
            return;
        }
        let prel = lba.wrapping_sub(PART_START);
        if prel == 0 || prel == 6 {
            self.boot_sector(out);
            return;
        }
        if prel == 1 {
            self.fsinfo(out);
            return;
        }
        // FAT region: [RESERVED, RESERVED + NFATS*fat_sectors).
        if (RESERVED..RESERVED + NFATS * self.fat_sectors).contains(&prel) {
            let fat_index = (prel - RESERVED) % self.fat_sectors; // sector within a FAT
            self.fat_sector(fat_index, out);
            return;
        }
        // Root directory (cluster 2).
        if lba == self.cluster_lba(ROOT_CLUSTER) {
            self.root_dir(out);
        }
    }

    fn mbr(&self, out: &mut [u8; 512]) {
        let pe = 446;
        out[pe] = 0x00;
        out[pe + 1..pe + 4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        out[pe + 4] = 0x0C; // FAT32 LBA
        out[pe + 5..pe + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        le(&mut out[pe + 8..], PART_START, 4);
        le(&mut out[pe + 12..], self.part_total, 4);
        out[510] = 0x55;
        out[511] = 0xAA;
    }

    fn boot_sector(&self, out: &mut [u8; 512]) {
        out[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        out[3..11].copy_from_slice(b"MSWIN4.1");
        le(&mut out[11..], BLOCK, 2);
        out[13] = 1; // sectors per cluster
        le(&mut out[14..], RESERVED, 2);
        out[16] = NFATS as u8;
        out[21] = 0xF8; // media
        le(&mut out[24..], 63, 2);
        le(&mut out[26..], 255, 2);
        le(&mut out[28..], PART_START, 4); // hidden sectors
        le(&mut out[32..], self.part_total, 4);
        le(&mut out[36..], self.fat_sectors, 4);
        le(&mut out[44..], ROOT_CLUSTER, 4);
        le(&mut out[48..], 1, 2); // FSInfo sector
        le(&mut out[50..], 6, 2); // backup boot sector
        out[64] = 0x80;
        out[66] = 0x29; // extended boot signature
        le(&mut out[67..], 0x5353_4E44, 4); // volume id
        out[71..82].copy_from_slice(b"SONDE      ");
        out[82..90].copy_from_slice(b"FAT32   ");
        out[510] = 0x55;
        out[511] = 0xAA;
    }

    fn fsinfo(&self, out: &mut [u8; 512]) {
        le(&mut out[0..], 0x4161_5252, 4);
        le(&mut out[484..], 0x6141_7272, 4);
        le(&mut out[488..], 0xFFFF_FFFF, 4); // free count unknown
        le(&mut out[492..], 0xFFFF_FFFF, 4); // next free unknown
        out[508..512].copy_from_slice(&[0x00, 0x00, 0x55, 0xAA]);
    }

    /// One 512-byte sector of the FAT (128 entries), computed from the chains.
    fn fat_sector(&self, sector: u32, out: &mut [u8; 512]) {
        let first = sector * 128; // first cluster number this sector covers
        for i in 0..128u32 {
            let cl = first + i;
            let val: u32 = if cl == 0 {
                0x0FFF_FFF8
            } else if cl == 1 || cl == ROOT_CLUSTER {
                0x0FFF_FFFF // reserved + single-cluster root dir
            } else if let Some((f, off)) = self.file_at(cl) {
                if off + 1 == f.n_clusters { 0x0FFF_FFFF } else { cl + 1 }
            } else {
                0 // free
            };
            le(&mut out[(i * 4) as usize..], val, 4);
        }
    }

    fn root_dir(&self, out: &mut [u8; 512]) {
        for (i, f) in self.files.iter().enumerate().take(16) {
            let e = &mut out[i * 32..i * 32 + 32];
            e[0..11].copy_from_slice(&f.name);
            e[11] = 0x20; // archive
            le(&mut e[20..], f.first_cluster >> 16, 2);
            le(&mut e[26..], f.first_cluster & 0xFFFF, 2);
            le(&mut e[28..], f.len, 4);
        }
    }
}

// Keep DATA_START_LBA referenced so a future layout check can assert runs live
// where the extractor expects; silences unused-import churn during the split.
const _: u32 = DATA_START_LBA;
