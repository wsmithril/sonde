//! ELF → UF2 converter for the XIAO nRF52840.
//!
//! Reads flash addresses directly from the ELF PT_LOAD segments — the linker
//! script (memory.x) is already embedded in the ELF, so no hardcoded base
//! address is needed. Each LOAD segment with a non-zero physical address and
//! non-zero file size becomes a set of UF2 blocks at that exact address.
//!
//! Output: sonde.uf2 in the workspace root.

use object::{Object, ObjectSegment, SegmentFlags};
use std::path::PathBuf;

// ── UF2 constants ─────────────────────────────────────────────────────────────

const MAGIC0: u32 = 0x0A324655; // "UF2\n"
const MAGIC1: u32 = 0x9E5D5157;
const MAGIC_END: u32 = 0x0AB16F30;
const FLAGS: u32 = 0x0000_2000; // familyID present
const FAMILY: u32 = 0xADA5_2840; // Adafruit / Seeed nRF52840

/// Payload bytes written to flash per UF2 block.
const CHUNK: usize = 256;

/// Total data-area bytes per 512-byte UF2 block.
/// 512 − 32 (header) − 4 (final magic) = 476.
const DATA_AREA: usize = 476;

// ── ELF parsing ───────────────────────────────────────────────────────────────

/// A contiguous region of data to be placed at a specific flash address.
struct FlashRegion {
    addr: u32,
    data: Vec<u8>,
}

/// Extracts all LOAD segments with non-zero physical addresses and file sizes.
fn extract_load_segments(elf_data: &[u8]) -> Vec<FlashRegion> {
    let obj = object::File::parse(elf_data)
        .expect("failed to parse ELF — is this a valid ARM firmware binary?");

    let mut regions: Vec<FlashRegion> = Vec::new();

    for seg in obj.segments() {
        if let SegmentFlags::Elf { p_flags } = seg.flags() {
            if p_flags == 0 {
                continue;
            }
        }

        let addr = seg.address() as u32;
        if addr == 0 {
            continue;
        }

        let data = match seg.data() {
            Ok(d) if !d.is_empty() => d.to_vec(),
            _ => continue,
        };

        regions.push(FlashRegion { addr, data });
    }

    regions.sort_by_key(|r| r.addr);
    regions
}

// ── UF2 encoding ──────────────────────────────────────────────────────────────

fn to_uf2(regions: &[FlashRegion]) -> Vec<u8> {
    let total_blocks: usize = regions
        .iter()
        .map(|r| (r.data.len() + CHUNK - 1) / CHUNK)
        .sum();

    let mut out = Vec::with_capacity(total_blocks * 512);
    let mut block_num: usize = 0;

    for region in regions {
        for (chunk_idx, chunk) in region.data.chunks(CHUNK).enumerate() {
            let target_addr = region.addr + (chunk_idx * CHUNK) as u32;

            for word in [
                MAGIC0,
                MAGIC1,
                FLAGS,
                target_addr,
                CHUNK as u32,
                block_num as u32,
                total_blocks as u32,
                FAMILY,
            ] {
                out.extend_from_slice(&word.to_le_bytes());
            }

            out.extend_from_slice(chunk);
            out.resize(out.len() + DATA_AREA - chunk.len().min(DATA_AREA), 0u8);

            out.extend_from_slice(&MAGIC_END.to_le_bytes());

            debug_assert_eq!(out.len(), (block_num + 1) * 512);
            block_num += 1;
        }
    }

    out
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run(elf_path: &str) {
    let elf_path = PathBuf::from(elf_path);
    let out_uf2 = PathBuf::from("sonde.uf2");

    let elf_data = std::fs::read(&elf_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", elf_path.display()));

    let regions = extract_load_segments(&elf_data);
    if regions.is_empty() {
        eprintln!("error: no loadable flash segments found in ELF");
        std::process::exit(1);
    }

    let uf2 = to_uf2(&regions);
    std::fs::write(&out_uf2, &uf2).unwrap_or_else(|e| panic!("cannot write sonde.uf2: {e}"));

    let total_fw_bytes: usize = regions.iter().map(|r| r.data.len()).sum();
    eprintln!(
        "→ {} ({} blocks, {} bytes across {} segment(s))",
        out_uf2.display(),
        uf2.len() / 512,
        total_fw_bytes,
        regions.len(),
    );
    eprintln!(
        "  Flash addresses: {}",
        regions
            .iter()
            .map(|r| format!("0x{:08x}+{}", r.addr, r.data.len()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!("  Double-tap XIAO reset, then copy sonde.uf2 to the XIAO-SENSE bootloader drive.");
}
