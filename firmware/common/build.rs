use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Magic tag written at the head of the external-flash asset image; the firmware
/// treats the image as valid (and lookups as available) only when it matches.
/// ASCII "BSA1" (BLE-Sniff Assets, v1).
const ASSET_MAGIC: u32 = 0x4253_4131;

/// Header size reserved at the front of the asset image. The firmware writes the
/// `{magic, len, crc}` header here *last* during provisioning (so a partial write
/// never looks valid); sections start at `HDR_SIZE`. Kept 4-byte aligned.
const HDR_SIZE: u32 = 16;

/// Records per sparse-index block, shared by every packed table (OUI + the SIG
/// `(u16, name)` tables). Must match `BLOCK` in the firmware decoder.
const BLOCK: usize = 64;

fn main() {
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // Linker memory layout + link args live in each binary crate's build.rs
    // (`firmware/usb`, `firmware/headless`), because `rustc-link-arg-bins` does
    // not propagate from a library dependency's build script. This crate is a
    // library and only generates the decoder name tables below.

    // ── Appearance table (stays internal) ─────────────────────────────────────
    // Small (~10 KB) and needed even on an unprovisioned device, so it remains a
    // baked-in `&[(u16, &str)]` literal for direct binary search.
    generate_appearance_table(out);

    // ── Other small core tables (also internal) ───────────────────────────────
    // AD types are looked up for every AD structure of every packet, and URI
    // schemes are ~2 KB; both are cheaper to keep in internal flash than to
    // reach through the external-flash asset path.
    generate_u16_table(out, "../../assets/ad_types.yaml", "value",
        "AD_TYPE_NAMES", "ad_type_names.rs", 40);
    generate_u16_table(out, "../../assets/uri_schemes.yaml", "value",
        "URI_SCHEMES", "uri_schemes.rs", 100);

    // ── Big lookup tables → external QSPI flash asset image ────────────────────
    // The IEEE MA-L (~486 KB) and long-prefix (~200 KB) address tables, the
    // Company-ID (~110 KB) table and the UUID-name (~25 KB) table live outside
    // internal flash. Their bulk data is packed into a single asset image
    // streamed to the on-board 2 MB QSPI flash (memory-mapped XIP at
    // 0x1200_0000) during provisioning; only small sparse search indices (and the
    // OUI alphabet/dictionary/parent lists) stay internal. See src/decoder/asset.rs.
    let company = parse_company();
    let uuid = parse_uuid();
    let oui = build_oui();

    // Pack the SIG tables the same way as OUI: records `[Δkey varint][u8 len]
    // [UTF-8 bytes]` (Δ resets to 0 each BLOCK) into a section, plus a small
    // internal sparse checkpoint index. Names are short, so no BPE (QSPI has room).
    let (company_sec, company_idx) = pack_u16_table(company);
    let (uuid_sec, uuid_idx) = pack_u16_table(uuid);

    // Assemble the image payload (sections concatenated, no header). The firmware
    // reserves HDR_SIZE bytes at the front, so on-device XIP offsets are
    // `HDR_SIZE + <section offset within payload>`.
    let mut payload: Vec<u8> = Vec::new();
    let mut sections: Vec<(&str, u32, u32)> = Vec::new();
    for (name, sec) in [
        ("OUI", &oui.mal_blob),
        ("OUISUB", &oui.sub_blob),
        ("COMPANY", &company_sec),
        ("UUID", &uuid_sec),
    ] {
        sections.push((name, HDR_SIZE + payload.len() as u32, sec.len() as u32));
        payload.extend_from_slice(sec);
    }
    let crc = crc32(&payload);

    // Write the image where the `builder` provision subcommand looks for it, in
    // both OUT_DIR and the workspace `target/` dir.
    fs::write(out.join("assets_blob.bin"), &payload).unwrap();
    if let Some(ws) = workspace_target(out) {
        let _ = fs::write(ws.join("assets_blob.bin"), &payload);
    }

    // Emit the internal generated sources.
    emit_oui_tables(out, &oui);
    emit_index(out, "company_index.rs", "COMPANY_INDEX", &company_idx);
    emit_index(out, "uuid_index.rs", "UUID_INDEX", &uuid_idx);
    emit_asset_meta(out, &sections, payload.len() as u32, crc);

    // Informational, not a warning: cargo only renders `cargo:warning=` inline,
    // so emit as plain build-script stderr (visible with `cargo build -vv`).
    let mut summary = String::new();
    for (name, _, len) in &sections {
        let _ = write!(summary, "{} {} B, ", name.to_lowercase(), len);
    }
    eprintln!(
        "asset image: {}total {} B (of 0x200000), crc32 0x{:08X}",
        summary,
        payload.len(),
        crc
    );
}

/// Locate the workspace `target/` directory by walking up from `OUT_DIR`
/// (`.../target/<triple>/<profile>/build/<pkg>/out`).
fn workspace_target(out: &Path) -> Option<PathBuf> {
    out.ancestors()
        .find(|p| p.file_name() == Some(OsStr::new("target")))
        .map(|p| p.to_path_buf())
}

// ── SIG YAML parsing ──────────────────────────────────────────────────────────

/// Parse a flat SIG YAML list of `- <id_key>: 0xNNNN` / `name: '...'` pairs into
/// `(u16, name)` entries. `id_key` is `value` (company ids) or `uuid`.
fn parse_kv_u16(yaml: &str, id_key: &str) -> Vec<(u16, String)> {
    let value_prefix = format!("{id_key}:");
    let mut entries: Vec<(u16, String)> = Vec::new();
    let mut pending: Option<u16> = None;
    for line in yaml.lines() {
        let t = line.trim_start();
        let after_dash = t.strip_prefix('-').map(str::trim_start).unwrap_or(t);
        if let Some(rest) = after_dash.strip_prefix(&value_prefix) {
            let v = rest.trim();
            let v = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")).unwrap_or(v);
            pending = u16::from_str_radix(v, 16).ok();
        } else if let Some(rest) = after_dash.strip_prefix("name:")
            && let Some(id) = pending.take()
        {
            entries.push((id, yaml_unquote(rest.trim())));
        }
    }
    entries
}

/// `../../assets/company_identifiers.yaml` → `(u16, name)` entries.
fn parse_company() -> Vec<(u16, String)> {
    const SRC: &str = "../../assets/company_identifiers.yaml";
    println!("cargo:rerun-if-changed={SRC}");
    let yaml = fs::read_to_string(SRC).unwrap_or_else(|e| panic!("failed to read {SRC}: {e}"));
    let entries = parse_kv_u16(&yaml, "value");
    assert!(
        entries.len() > 1000,
        "parsed only {} company identifiers — YAML format may have changed",
        entries.len()
    );
    entries
}

/// SIG 16-bit UUID names → `(u16, name)` entries. Merges every SIG list that
/// shares the `- uuid:`/`name:` shape into one table: the service, member and
/// SDO UUIDs an advertisement can carry, plus the GATT declaration, descriptor
/// and characteristic UUIDs a service discovery walks over. The ranges do not
/// overlap (services 0x18xx/0xFCxx-0xFFxx, declarations 0x28xx, descriptors
/// 0x29xx, characteristics 0x2Axx-0x2Bxx), so one table serves both callers.
fn parse_uuid() -> Vec<(u16, String)> {
    const SRCS: [&str; 6] = [
        "../../assets/service_uuids.yaml",
        "../../assets/member_uuids.yaml",
        "../../assets/sdo_uuids.yaml",
        "../../assets/declarations.yaml",
        "../../assets/descriptors.yaml",
        "../../assets/characteristic_uuids.yaml",
    ];
    let mut entries: Vec<(u16, String)> = Vec::new();
    for src in SRCS {
        println!("cargo:rerun-if-changed={src}");
        let yaml = fs::read_to_string(src).unwrap_or_else(|e| panic!("failed to read {src}: {e}"));
        entries.extend(parse_kv_u16(&yaml, "uuid"));
    }
    assert!(
        entries.len() > 1000,
        "parsed only {} UUID names — YAML format may have changed",
        entries.len()
    );
    entries
}

/// A flat SIG YAML list → a sorted `&[(u16, &str)]` literal in `OUT_DIR/<file>`.
/// Used for the small core tables that stay in internal flash because they are
/// consulted on every packet (AD types) or are only a couple of KB (URI
/// schemes), rather than going into the external-flash asset image.
fn generate_u16_table(out: &Path, src: &str, id_key: &str, static_name: &str, file: &str, min: usize) {
    println!("cargo:rerun-if-changed={src}");
    let yaml = fs::read_to_string(src).unwrap_or_else(|e| panic!("failed to read {src}: {e}"));
    let mut entries = parse_kv_u16(&yaml, id_key);
    assert!(
        entries.len() >= min,
        "parsed only {} entries from {src} — YAML format may have changed",
        entries.len()
    );
    // A value listed twice (AD type 0x10 is both Device ID and Security Manager
    // TK Value, depending on where it appears) keeps its first listing.
    entries.sort_by_key(|&(id, _)| id);
    entries.dedup_by_key(|&mut (id, _)| id);

    let mut code = String::new();
    let _ = writeln!(
        code,
        "// Generated by build.rs from {src} — do not edit.\n\
         pub static {static_name}: &[(u16, &str)] = &["
    );
    for (id, name) in &entries {
        let _ = writeln!(code, "    (0x{:04X}, \"{}\"),", id, rust_escape(name));
    }
    code.push_str("];\n");
    fs::write(out.join(file), code).unwrap();
}

/// `../../assets/appearance_values.yaml` → `OUT_DIR/appearance_names.rs`.
///
/// The file nests `- category: 0xNNN` blocks, each with a `name:` and an
/// optional `subcategory:` list of `- value: 0xNN`/`name:` pairs. The full
/// 16-bit appearance value is `(category << 6) | subcategory`, so the generic
/// category maps at subcategory 0 and each subcategory gets its own entry.
fn generate_appearance_table(out: &Path) {
    const SRC: &str = "../../assets/appearance_values.yaml";
    println!("cargo:rerun-if-changed={SRC}");
    let yaml = fs::read_to_string(SRC).unwrap_or_else(|e| panic!("failed to read {SRC}: {e}"));

    let mut entries: Vec<(u16, String)> = Vec::new();
    let mut cur_cat: u16 = 0;
    // (is_subcategory, id) armed by a `category:`/`value:` line, consumed by `name:`.
    let mut pending: Option<(bool, u16)> = None;
    for line in yaml.lines() {
        let t = line.trim_start();
        let after_dash = t.strip_prefix('-').map(str::trim_start).unwrap_or(t);
        if let Some(rest) = after_dash.strip_prefix("category:") {
            if let Some(v) = parse_hex_u16(rest.trim()) {
                cur_cat = v;
                pending = Some((false, v));
            }
        } else if let Some(rest) = after_dash.strip_prefix("value:") {
            if let Some(v) = parse_hex_u16(rest.trim()) {
                pending = Some((true, v));
            }
        } else if let Some(rest) = after_dash.strip_prefix("name:")
            && let Some((is_sub, id)) = pending.take()
        {
            let full = if is_sub { (cur_cat << 6) | (id & 0x3F) } else { cur_cat << 6 };
            entries.push((full, yaml_unquote(rest.trim())));
        }
    }
    assert!(
        entries.len() > 100,
        "parsed only {} appearance values — YAML format may have changed",
        entries.len()
    );

    entries.sort_by_key(|&(id, _)| id);
    entries.dedup_by_key(|&mut (id, _)| id);
    let mut code = String::new();
    let _ = writeln!(
        code,
        "// Generated by build.rs — do not edit.\n\
         pub static APPEARANCE_VALUES: &[(u16, &str)] = &["
    );
    for (id, name) in &entries {
        let _ = writeln!(code, "    (0x{:04X}, \"{}\"),", id, rust_escape(name));
    }
    code.push_str("];\n");
    fs::write(out.join("appearance_names.rs"), code).unwrap();
}

fn parse_hex_u16(v: &str) -> Option<u16> {
    let v = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")).unwrap_or(v);
    u16::from_str_radix(v, 16).ok()
}

/// Strip YAML quoting from a scalar. Single-quoted YAML escapes `'` as `''`;
/// double-quoted YAML uses backslash escapes. The SIG files only exercise the
/// simple cases, but handle both quote styles defensively.
fn yaml_unquote(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        s[1..s.len() - 1].replace("''", "'")
    } else if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].replace("\\\"", "\"").replace("\\\\", "\\")
    } else {
        s.to_string()
    }
}

/// Escape a string for embedding inside a Rust `"..."` literal.
fn rust_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ── Packed `(u16, name)` section ───────────────────────────────────────────────

/// Pack `(u16, name)` entries into an asset-image section and a sparse checkpoint
/// index. Entries are sorted and deduped by key. Section layout mirrors the OUI
/// blob: each record is `[Δkey varint][u8 len][UTF-8 name bytes]`, with Δkey
/// resetting to 0 at every BLOCK-th record so a block decodes from its index
/// checkpoint alone. Returns `(section_bytes, index)` where `index[i]` is
/// `(key, section-relative byte offset)` for the i-th block's first record.
fn pack_u16_table(mut entries: Vec<(u16, String)>) -> (Vec<u8>, Vec<(u16, u32)>) {
    entries.sort_by_key(|&(id, _)| id);
    entries.dedup_by_key(|&mut (id, _)| id);

    let mut sec: Vec<u8> = Vec::new();
    let mut index: Vec<(u16, u32)> = Vec::new();
    let mut prev = 0u32;
    for (i, (key, name)) in entries.iter().enumerate() {
        let key = *key as u32;
        let delta = if i % BLOCK == 0 {
            index.push((key as u16, sec.len() as u32));
            0
        } else {
            key - prev
        };
        write_varint(&mut sec, delta);
        let bytes = name.as_bytes();
        assert!(bytes.len() <= 255, "name too long ({} B): {}", bytes.len(), name);
        sec.push(bytes.len() as u8);
        sec.extend_from_slice(bytes);
        prev = key;
    }
    (sec, index)
}

// ── IEEE MAC address registry table generation ────────────────────────────────
//
// IEEE assigns MAC blocks at four sizes, each published as its own CSV:
//
//   MA-L (oui.csv)    ~40k orgs keyed by a 24-bit OUI — the top three octets.
//   MA-M (mam.csv)    ~6.5k orgs keyed by 28 bits, carving up 434 MA-L blocks.
//   MA-S (oui36.csv)  ~7k orgs keyed by 36 bits, carving up 3 MA-L blocks.
//   IAB  (iab.csv)    ~4.5k orgs keyed by 36 bits, carving up 2 more. Closed to
//                     new assignments; retained for devices already in the field.
//
// A block that has been subdivided is listed in MA-L under the placeholder name
// "IEEE Registration Authority", so resolving one of its MACs needs the longer
// registries. The three of them are disjoint by parent — a given 24-bit block is
// carved up by exactly one scheme — which build_oui asserts, and which lets the
// extension width be a per-parent property rather than a per-record one.
//
// Names total ~1.3 MB across all four. We compress them with byte-pair encoding
// (BPE) and store the records in self-delimiting blobs with sparse binary-search
// indices. The blobs are *sections of the external asset image*; only the small
// alphabet/dictionary/index literals stay internal (see src/decoder/asset.rs):
//
//   * Alphabet — the distinct name bytes, remapped to small symbol ids 0..A so
//     the remaining 256-A id values are free for BPE tokens.
//   * Dictionary — up to (256-A) BPE tokens, each a `(left, right)` symbol pair
//     (symbols are literal ids < A or nested token ids), expanded recursively.
//     One dictionary is trained over all four registries and shared by both
//     blobs, so the long-prefix names ride on tokens the MA-L corpus paid for.
//   * Blobs — records sorted by key ascending, each `[Δkey varint][enclen]
//     [enc bytes]`. The Δkey resets to 0 at the start of each BLOCK-record group
//     so any block can be decoded from its index checkpoint alone.
//   * Indices — `(key, byte offset)` for every BLOCK-th record, for binary
//     search down to a block that is then scanned linearly.
//
// The MA-L blob is keyed by the 24-bit prefix directly. The long-prefix blob
// holds MA-M + MA-S + IAB in one section, keyed by
//
//     (parent ordinal << 12) | extension
//
// where the ordinal is the parent's index in the sorted SUB_PARENTS list and the
// extension is the 4 bits (MA-M) or 12 bits (MA-S, IAB) below the parent OUI.
// That keeps the key inside a u32 — a bare 36-bit prefix would not fit — and
// keeps records dense within a parent so the deltas stay one byte.

/// The generated IEEE address tables: two asset-image sections plus the internal
/// literals needed to search them.
struct OuiTables {
    /// MA-L section, keyed by 24-bit OUI.
    mal_blob: Vec<u8>,
    /// MA-M + MA-S + IAB section, keyed by `(ordinal << 12) | ext`.
    sub_blob: Vec<u8>,
    alpha: Vec<u8>,
    dict: Vec<(u8, u8)>,
    mal_index: Vec<(u32, u32)>,
    sub_index: Vec<(u32, u32)>,
    /// Sorted 24-bit prefixes of every subdivided block; the position of a
    /// prefix here is the ordinal its records are keyed by.
    sub_parents: Vec<u32>,
    /// The subset of `sub_parents` carved into 36-bit blocks (MA-S and IAB), so
    /// the firmware knows to take 12 extension bits rather than 4.
    sub36: Vec<u32>,
}

/// Parse one long-prefix registry into `(parent24, ext, folded name)` rows.
/// `hex_digits` is the assignment width in hex characters — 7 for a 28-bit MA-M
/// block, 9 for a 36-bit MA-S or IAB one — of which the leading 6 are the parent
/// OUI and the rest are the extension.
fn parse_long_registry(src: &str, registry: &str, hex_digits: usize, min: usize)
    -> Vec<(u32, u32, Vec<u8>)>
{
    println!("cargo:rerun-if-changed={src}");
    let csv = fs::read_to_string(src).unwrap_or_else(|e| panic!("failed to read {src}: {e}"));

    let mut seen = std::collections::HashSet::new();
    let mut rows: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    for line in csv.lines() {
        let fields = parse_csv_row(line);
        if fields.len() < 3 || fields[0] != registry {
            continue;
        }
        let asg = fields[1].trim();
        if asg.len() != hex_digits {
            continue;
        }
        let (parent, ext) = match (
            u32::from_str_radix(&asg[..6], 16),
            u32::from_str_radix(&asg[6..], 16),
        ) {
            (Ok(p), Ok(e)) => (p, e),
            _ => continue,
        };
        if !seen.insert((parent, ext)) {
            continue; // duplicate assignment — keep the first
        }
        rows.push((parent, ext, ascii_fold(fields[2].trim())));
    }
    assert!(
        rows.len() > min,
        "parsed only {} {} rows from {} — CSV format may have changed",
        rows.len(),
        registry,
        src
    );
    rows
}

/// Parse + BPE-compress all four IEEE registries into the asset-image sections
/// and the internal search literals.
fn build_oui() -> OuiTables {
    const SRC: &str = "../../assets/oui.csv";
    println!("cargo:rerun-if-changed={SRC}");
    let csv = fs::read_to_string(SRC).unwrap_or_else(|e| panic!("failed to read {SRC}: {e}"));

    // Parse MA-L rows → (prefix, folded name), dedup keep-first, sort by prefix.
    let mut seen = std::collections::HashSet::new();
    let mut recs: Vec<(u32, Vec<u8>)> = Vec::new();
    for line in csv.lines() {
        let fields = parse_csv_row(line);
        if fields.len() < 3 || fields[0] != "MA-L" {
            continue;
        }
        let asg = fields[1].trim();
        if asg.len() != 6 {
            continue;
        }
        let prefix = match u32::from_str_radix(asg, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !seen.insert(prefix) {
            continue; // duplicate OUI assignment — keep the first
        }
        recs.push((prefix, ascii_fold(fields[2].trim())));
    }
    recs.sort_by_key(|&(p, _)| p);
    assert!(
        recs.len() > 30_000,
        "parsed only {} OUI rows — CSV format may have changed",
        recs.len()
    );

    // The three subdivided-block registries. MA-M carves a parent into 16 blocks
    // (4 extension bits); MA-S and IAB carve one into 4096 (12 bits).
    let mam = parse_long_registry("../../assets/mam.csv", "MA-M", 7, 6_000);
    let mas = parse_long_registry("../../assets/oui36.csv", "MA-S", 9, 7_000);
    let iab = parse_long_registry("../../assets/iab.csv", "IAB", 9, 4_000);

    let parents = |rows: &[(u32, u32, Vec<u8>)]| -> std::collections::BTreeSet<u32> {
        rows.iter().map(|&(p, _, _)| p).collect()
    };
    let p_mam = parents(&mam);
    let mut p_wide = parents(&mas);
    p_wide.extend(parents(&iab));
    // Per-parent extension width only works because no block is carved up by two
    // schemes at once. Assert it rather than trust it: a future registry that
    // breaks this would otherwise silently mis-key every record under that block.
    let both: Vec<u32> = p_mam.intersection(&p_wide).copied().collect();
    assert!(
        both.is_empty(),
        "OUI blocks subdivided as both MA-M and MA-S/IAB: {:06X?}",
        both
    );

    let mut sub_parents: Vec<u32> = p_mam.union(&p_wide).copied().collect();
    sub_parents.sort_unstable();
    let sub36: Vec<u32> = p_wide.into_iter().collect();
    let ordinal: std::collections::HashMap<u32, u32> = sub_parents
        .iter()
        .enumerate()
        .map(|(i, &p)| (p, i as u32))
        .collect();

    // Long-prefix records keyed by (ordinal << 12) | ext, sorted ascending. The
    // extension is at most 12 bits, so a parent's records never collide with its
    // neighbours'.
    let mut subs: Vec<(u32, Vec<u8>)> = mam
        .into_iter()
        .chain(mas)
        .chain(iab)
        .map(|(parent, ext, name)| {
            assert!(ext < 4096, "extension {:X} wider than 12 bits", ext);
            (ordinal[&parent] << 12 | ext, name)
        })
        .collect();
    subs.sort_by_key(|&(k, _)| k);

    // Alphabet: distinct name bytes across all four registries, sorted, remapped
    // to ids 0..A.
    let names = || recs.iter().map(|(_, n)| n).chain(subs.iter().map(|(_, n)| n));
    let mut chars: Vec<u8> = {
        let mut set = std::collections::HashSet::new();
        for n in names() {
            for &b in n {
                set.insert(b);
            }
        }
        set.into_iter().collect()
    };
    chars.sort_unstable();
    let alpha = chars.len();
    assert!(alpha < 256, "OUI alphabet {} too large for BPE", alpha);
    let cmap: std::collections::HashMap<u8, u8> =
        chars.iter().enumerate().map(|(i, &b)| (b, i as u8)).collect();
    let mut seqs: Vec<Vec<u8>> = names()
        .map(|n| n.iter().map(|b| cmap[b]).collect())
        .collect();

    // BPE: greedily merge the most frequent adjacent pair into a new token until
    // the token id space (256-A) is exhausted or no pair repeats enough.
    let num_tokens = 256 - alpha;
    let mut dict: Vec<(u8, u8)> = Vec::new();
    for m in 0..num_tokens {
        let mut counts: std::collections::HashMap<(u8, u8), u32> = std::collections::HashMap::new();
        for s in &seqs {
            for w in s.windows(2) {
                *counts.entry((w[0], w[1])).or_default() += 1;
            }
        }
        // Pick the most frequent pair; break ties deterministically by pair value
        // so the table is reproducible across builds.
        let best = counts
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(&pair, &c)| (pair, c));
        let ((a, b), _count) = match best {
            Some(v) if v.1 >= 3 => v,
            _ => break,
        };
        let tid = (alpha + m) as u8;
        dict.push((a, b));
        for s in &mut seqs {
            let mut i = 0;
            while i + 1 < s.len() {
                if s[i] == a && s[i + 1] == b {
                    s[i] = tid;
                    s.remove(i + 1);
                } else {
                    i += 1;
                }
            }
        }
    }

    // Split the shared encoding back into the two sections, in the order the
    // `names()` iterator concatenated them.
    let sub_seqs = seqs.split_off(recs.len());
    let mal_keys: Vec<u32> = recs.iter().map(|&(p, _)| p).collect();
    let sub_keys: Vec<u32> = subs.iter().map(|&(k, _)| k).collect();
    let (mal_blob, mal_index) = pack_bpe_section(&mal_keys, &seqs);
    let (sub_blob, sub_index) = pack_bpe_section(&sub_keys, &sub_seqs);

    // Informational, not a warning: cargo only renders `cargo:warning=` inline,
    // so emit as plain build-script stderr (visible with `cargo build -vv`).
    eprintln!(
        "OUI table: {} MA-L orgs, {} tokens, blob {} B, index {} entries",
        recs.len(),
        dict.len(),
        mal_blob.len(),
        mal_index.len()
    );
    eprintln!(
        "OUI long-prefix table: {} orgs under {} parents ({} of them 36-bit), \
         blob {} B, index {} entries",
        subs.len(),
        sub_parents.len(),
        sub36.len(),
        sub_blob.len(),
        sub_index.len()
    );

    OuiTables {
        mal_blob,
        sub_blob,
        alpha: chars,
        dict,
        mal_index,
        sub_index,
        sub_parents,
        sub36,
    }
}

/// Pack BPE-encoded records into an asset-image section plus its sparse
/// checkpoint index. `keys` must be sorted ascending and parallel to `seqs`.
/// Each record is `[Δkey varint][u8 enclen][enc bytes]`, with Δkey resetting to
/// 0 at every BLOCK-th record so a block decodes from its checkpoint alone.
fn pack_bpe_section(keys: &[u32], seqs: &[Vec<u8>]) -> (Vec<u8>, Vec<(u32, u32)>) {
    let mut blob: Vec<u8> = Vec::new();
    let mut index: Vec<(u32, u32)> = Vec::new();
    let mut prev = 0u32;
    for (i, &key) in keys.iter().enumerate() {
        let delta = if i % BLOCK == 0 {
            index.push((key, blob.len() as u32));
            0
        } else {
            key - prev
        };
        write_varint(&mut blob, delta);
        let enc = &seqs[i];
        assert!(enc.len() <= 255, "encoded OUI name too long: {}", enc.len());
        blob.push(enc.len() as u8);
        blob.extend_from_slice(enc);
        prev = key;
    }
    (blob, index)
}

/// Emit `OUT_DIR/oui_table.rs` with the internal OUI alphabet, dictionary,
/// sparse indices, and subdivided-parent lists. The name blobs themselves live
/// in the external asset image.
fn emit_oui_tables(out: &Path, t: &OuiTables) {
    let mut code = String::new();
    let _ = writeln!(code, "// Generated by build.rs — do not edit.");
    let _ = write!(code, "pub static OUI_ALPHABET: &[u8] = &[");
    for &b in &t.alpha {
        let _ = write!(code, "{},", b);
    }
    let _ = writeln!(code, "];");
    let _ = write!(code, "pub static OUI_DICT: &[(u8, u8)] = &[");
    for &(a, b) in &t.dict {
        let _ = write!(code, "({},{}),", a, b);
    }
    let _ = writeln!(code, "];");
    let _ = write!(code, "pub static OUI_SUB_PARENTS: &[u32] = &[");
    for &p in &t.sub_parents {
        let _ = write!(code, "0x{:06X},", p);
    }
    let _ = writeln!(code, "];");
    let _ = write!(code, "pub static OUI_SUB36: &[u32] = &[");
    for &p in &t.sub36 {
        let _ = write!(code, "0x{:06X},", p);
    }
    let _ = writeln!(code, "];");
    let _ = writeln!(code, "pub static OUI_INDEX: &[(u32, u32)] = &[");
    for &(p, o) in &t.mal_index {
        let _ = writeln!(code, "    (0x{:06X},{}),", p, o);
    }
    let _ = writeln!(code, "];");
    let _ = writeln!(code, "pub static OUI_SUB_INDEX: &[(u32, u32)] = &[");
    for &(k, o) in &t.sub_index {
        let _ = writeln!(code, "    (0x{:06X},{}),", k, o);
    }
    let _ = writeln!(code, "];");
    fs::write(out.join("oui_table.rs"), code).unwrap();
}

/// Emit a small internal `pub static <ident>: &[(u16, u32)]` sparse checkpoint
/// index (block key → section-relative byte offset).
fn emit_index(out: &Path, file: &str, ident: &str, index: &[(u16, u32)]) {
    let mut code = String::new();
    let _ = writeln!(code, "// Generated by build.rs — do not edit.");
    let _ = writeln!(code, "pub static {ident}: &[(u16, u32)] = &[");
    for &(k, o) in index {
        let _ = writeln!(code, "    (0x{:04X},{}),", k, o);
    }
    let _ = writeln!(code, "];");
    fs::write(out.join(file), code).unwrap();
}

/// Emit `OUT_DIR/asset_meta.rs`: the header layout, per-section XIP offsets and
/// lengths, and the image length + CRC the firmware validates after
/// provisioning. `sections` gives each section's `(name, xip offset, length)` in
/// image order; the name is uppercased into the `<NAME>_XIP_OFF` / `<NAME>_LEN`
/// constant pair the decoder reads.
fn emit_asset_meta(out: &Path, sections: &[(&str, u32, u32)], asset_len: u32, crc: u32) {
    let mut code = String::new();
    let _ = writeln!(code, "// Generated by build.rs — do not edit.");
    let _ = writeln!(code, "pub const ASSET_MAGIC: u32 = 0x{ASSET_MAGIC:08X};");
    let _ = writeln!(code, "pub const HDR_SIZE: u32 = {HDR_SIZE};");
    let _ = writeln!(code, "pub const ASSET_LEN: u32 = {asset_len};");
    let _ = writeln!(code, "pub const ASSET_CRC32: u32 = 0x{crc:08X};");
    for &(name, off, len) in sections {
        let _ = writeln!(code, "pub const {name}_XIP_OFF: u32 = {off};");
        let _ = writeln!(code, "pub const {name}_LEN: u32 = {len};");
    }
    fs::write(out.join("asset_meta.rs"), code).unwrap();
}

/// Minimal RFC-4180-ish CSV field splitter: handles double-quoted fields with
/// embedded commas and doubled `""` escapes. Sufficient for the IEEE OUI export.
fn parse_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_quotes {
            if c == '"' {
                if i + 1 < bytes.len() && bytes[i + 1] == '"' {
                    cur.push('"');
                    i += 1;
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == ',' {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
        i += 1;
    }
    fields.push(cur);
    fields
}

/// Fold a name to ASCII: pass ASCII through, map common Latin-1 accented letters
/// to their base letter, and replace anything else with '?'. Vendor names are
/// for at-a-glance identification, so lossy folding of the ~0.5% non-ASCII names
/// is acceptable and keeps the symbol alphabet compact.
fn ascii_fold(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii() {
            out.push(ch as u8);
            continue;
        }
        let base = match ch {
            'À'..='Å' | 'à'..='å' | 'Ā'..='ą' => 'a',
            'Ç' | 'ç' | 'Ć'..='č' => 'c',
            'È'..='Ë' | 'è'..='ë' | 'Ē'..='ě' => 'e',
            'Ì'..='Ï' | 'ì'..='ï' | 'Ĩ'..='ı' => 'i',
            'Ñ' | 'ñ' | 'Ń'..='ň' => 'n',
            'Ò'..='Ö' | 'Ø' | 'ò'..='ö' | 'ø' | 'Ō'..='ő' => 'o',
            'Ù'..='Ü' | 'ù'..='ü' | 'Ũ'..='ų' => 'u',
            'Ý' | 'ý' | 'ÿ' => 'y',
            'ß' => 's',
            _ => '?',
        };
        out.push(base as u8);
    }
    out
}

/// LEB128 unsigned varint append.
fn write_varint(v: &mut Vec<u8>, mut x: u32) {
    loop {
        let byte = (x & 0x7F) as u8;
        x >>= 7;
        if x != 0 {
            v.push(byte | 0x80);
        } else {
            v.push(byte);
            break;
        }
    }
}

/// CRC-32/ISO-HDLC (reflected, poly 0xEDB88320) — must match the firmware's
/// provisioning verify and the host `builder` crate so the checksum baked into
/// `asset_meta.rs` matches what the device computes over the written bytes.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
