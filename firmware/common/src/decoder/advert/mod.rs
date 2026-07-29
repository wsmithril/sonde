//! Advertising-payload deep decoders, one module per vendor or service.
//!
//! Every module here exposes a unit struct implementing [`VendorDecoder`] and is
//! reached only through the [`DECODERS`] registry, keyed by SIG Company ID
//! (manufacturer data, AD 0xFF) or 16-bit service UUID (service data, AD 0x16).
//! A module may claim keys in both spaces — several vendors ship the same
//! product state under a Company ID on one device and a service UUID on
//! another — so the tree stays flat and the registry, not the directory, is
//! what says which decoder owns a key.
//!
//! Connection-oriented wire protocols live in [`crate::decoder::protocol`].

// Formatting helpers shared with the rest of the decoder. Imported once here so
// each vendor module keeps reaching them as `super::…`.
use super::{emit, emit_oui_vendor, hexdump, write_hex, write_mac_be, LogStr};

mod alibaba;
mod amap;
mod amazon;
mod apple;
mod artiming;
mod baidu;
mod bandxi;
mod bluetrum;
mod bose;
mod eddystone;
mod edifier;
mod fastpair;
mod google;
mod gree;
mod haier;
mod harman;
mod honor;
mod hp;
mod huawei;
mod jieli;
mod leaudio;
mod macframe;
pub(super) mod mesh;
mod miconnect;
mod microsoft;
mod midea;
mod mobike;
mod motive;
mod nintendo;
mod olafriends;
mod oplus;
mod opple;
mod oppo;
mod qualcomm;
mod samsung;
mod sony;
mod soundaudio;
mod telink;
mod ti;
mod tomtom;
mod tuya;
mod utec;
mod vivo;
mod xiaomi;
mod yichip;

// ── Vendor-decoder trait system ───────────────────────────────────────────────
// Each vendor module exposes a unit struct implementing `VendorDecoder`, declaring
// the manufacturer Company IDs (AD 0xFF) and/or service UUID16s (AD 0x16) it
// handles. `dispatch` scans the `DECODERS` registry for a claimant; adding a
// vendor is one new impl + one registry line — no edit to the central match.

/// Which advertising frame a body came from — selects the ID space to match on.
pub(super) enum FrameKind {
    /// Manufacturer-specific data (AD 0xFF), keyed by SIG Company ID.
    Mfg,
    /// Service data (AD 0x16), keyed by 16-bit service UUID.
    Service,
}

/// Context handed to a `VendorDecoder`: the matched key, its frame kind, and the
/// hexdump base offset (the byte position of `body` within the AD structure).
pub(super) struct DecodeCtx {
    pub base: usize,
    pub key: u16,
    pub kind: FrameKind,
}

/// A vendor/service deep decoder. Declares the IDs it claims and decodes the
/// body that follows the 2-byte Company ID / service UUID.
pub(super) trait VendorDecoder: Sync {
    /// Manufacturer Company IDs handled (AD 0xFF). Empty if none.
    fn company_ids(&self) -> &'static [u16] { &[] }
    /// Service UUID16s handled (AD 0x16). Empty if none.
    fn service_uuids(&self) -> &'static [u16] { &[] }
    /// Decode `body` (the bytes after the matched 2-byte key).
    fn decode(&self, ctx: &DecodeCtx, body: &[u8]);
}

/// Registry of vendor decoders, scanned in order by `dispatch`.
static DECODERS: &[&dyn VendorDecoder] = &[
    &apple::Apple,
    &microsoft::Microsoft,
    &sony::Sony,
    &xiaomi::Xiaomi,
    &edifier::Edifier,
    &eddystone::Eddystone,
    &fastpair::FastPair,
    &google::Google,
    &huawei::Huawei,
    &honor::Honor,
    &utec::Utec,
    &leaudio::LeAudio,
    &mesh::BtMesh,
    &tuya::Tuya,
    &baidu::Baidu,
    &alibaba::Alibaba,
    &oppo::Oppo,
    &vivo::Vivo,
    &opple::Opple,
    &midea::Midea,
    &nintendo::Nintendo,
    &telink::Telink,
    &jieli::Jieli,
    &bluetrum::Bluetrum,
    &samsung::Samsung,
    &hp::Hp,
    &harman::Harman,
    &amazon::Amazon,
    &miconnect::MiConnect,
    &bose::Bose,
    &qualcomm::Qualcomm,
    &mobike::Mobike,
    &ti::TexasInstruments,
    &tomtom::TomTom,
    &haier::Haier,
    &artiming::ArTiming,
    &bandxi::BandXi,
    &soundaudio::SoundAudio,
    &gree::Gree,
    &olafriends::OlaFriends,
    &macframe::MacFrame,
    &oplus::Oplus,
    &amap::Amap,
    &motive::Motive,
    &yichip::Yichip,
];

/// Route `ctx`/`body` to the first registered decoder claiming `ctx.key` in the
/// matching ID space. Returns `false` if no decoder claimed it.
fn dispatch(ctx: &DecodeCtx, body: &[u8]) -> bool {
    for d in DECODERS {
        let keys = match ctx.kind {
            FrameKind::Mfg => d.company_ids(),
            FrameKind::Service => d.service_uuids(),
        };
        if keys.contains(&ctx.key) {
            d.decode(ctx, body);
            return true;
        }
    }
    false
}

pub(super) fn decode_mfg(data: &[u8]) {
    if data.len() < 2 { return; }
    let cid = u16::from_le_bytes([data[0], data[1]]);
    let body = &data[2..];
    let ctx = DecodeCtx { base: 2, key: cid, kind: FrameKind::Mfg };
    // An unknown vendor gets a raw body dump: the dump's ASCII gutter is where an
    // embedded model or firmware string shows up. It sits one level under the
    // MfgData container the caller already opened.
    if !dispatch(&ctx, body) {
        super::hexdump(body, 2, 6);
    }
}

/// Dispatch service data (AD type 0x16) by the leading 16-bit service UUID.
/// `adva` (the advertiser's on-air address) lets us flag beacons that place
/// their own BD_ADDR in the service payload instead of a real vendor structure.
pub(super) fn decode_service_data(data: &[u8], adva: Option<[u8; 6]>) {
    use core::fmt::Write;
    if data.len() < 2 { return; }
    let uuid = u16::from_le_bytes([data[0], data[1]]);
    let body = &data[2..]; // frame bytes follow the 16-bit service UUID

    // Some devices (e.g. under UUID 0x3802) advertise their own address as the
    // service payload. Detect the address in either byte order and label it
    // rather than presenting a meaningless "vendor" blob.
    if let Some(a) = adva {
        let mut rev = a;
        rev.reverse();
        if body.len() >= 6 && (body[..6] == a || body[..6] == rev) {
            let mut s: LogStr = LogStr::new();
            let _ = write!(s, "    own-address in service data (uuid=0x{:04X})\r\n", uuid);
            emit(s);
            return;
        }
    }

    let ctx = DecodeCtx { base: 2, key: uuid, kind: FrameKind::Service };
    // Unknown service UUID: dump the raw body one level under the ServiceData
    // container the caller already opened.
    if !dispatch(&ctx, body) {
        super::hexdump(body, 2, 6);
    }
}
