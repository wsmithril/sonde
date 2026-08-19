//! DESSMANN (德施曼) "小嘀" smart-lock command protocol over BLE GATT — the
//! write/notify channel of DESSMANN door locks. Frame format and command set
//! are extracted from the official `xiaodisdk-3.4.7` Android SDK (repos
//! `dessmann/XiaodiIfDemo`, `dessmann/Dessmann_xiaodisdk4demo_Android`).
//!
//! Transport: service `0xFFE0` (notify char `0xFFE4`) + service `0xFFE5`
//! (write char `0xFFE9`). Frames:
//! ```text
//!   [0xFE][0x01][cmd][len_hi][len_lo][payload ≤13][chk_hi][chk_lo]
//! ```
//! The checksum is the unsigned sum of frame bytes `[1..len-3]` (excluding the
//! `0xFE` header and the trailing two bytes), big-endian — mirroring the SDK's
//! `CRCUtil.a` exactly, quirks included.
//!
//! The SDK sends most commands in plaintext (`encrypted=false`); only the OPEN
//! paths (`0x03`, `0x39`) and the secret-key / challenge-MAC exchange are
//! protected. "Cipher capability" is probed via GET CHALLENGE (`0x61`): an
//! 8-byte challenge reply means the open path needs the sekey-derived MAC.
//!
//! HARDWARE-UNVERIFIED: the framing and command bytes come from the SDK, not an
//! observed exchange. Every response is logged raw so the framing can be
//! confirmed or corrected on a live lock.
#![allow(dead_code)]

use heapless::Vec;

/// The lock's write (TX) + notify (RX) command channel.
#[derive(Clone, Copy)]
pub struct Profile {
    pub write_h: u16,
    pub notify_h: u16,
}

/// A DESSMANN lock command. Each variant's value is its wire byte (hence
/// `#[repr(u8)]` — `cmd as u8` is the on-air command byte). Also carries a
/// readable name and whether issuing it changes device state (a door lock, a
/// password, an access record — not just reads).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    /// Read the firmware version. Safe.
    GetSoftwareVersion = 0x37,
    /// Read the lock's secret key. Safe (read-only) but sensitive: this is the
    /// key material the channel-protected commands authenticate with.
    GetSecretKey = 0x3A,
    /// Read the lock's SEID. Safe.
    GetSeid = 0x60,
    /// Request an 8-byte challenge; the cipher-capability probe. Safe.
    GetChallenge = 0x61,
    /// Open the lock (basic). State-changing.
    OpenBasic = 0x03,
    /// Sync the lock clock. State-changing.
    SyncTime = 0x23,
    /// Add a fingerprint. State-changing.
    AddFinger = 0x24,
    /// Add a mobile account. State-changing.
    AddMobileAccount = 0x25,
    /// Add a smart-key auth. State-changing.
    AddSmartKeyAuth = 0x26,
    /// Delete a fingerprint. State-changing.
    DelFinger = 0x28,
    /// Delete a mobile account. State-changing.
    DelMobileAccount = 0x29,
    /// Delete a smart key. State-changing.
    DelSmartKey = 0x2A,
    /// Update fingerprint attributes. State-changing.
    UpdFingerAttr = 0x2B,
    /// Update the open password. State-changing.
    UpdOpenPwd = 0x30,
    /// Register the lock device. State-changing.
    Register = 0x34,
    /// Clear the mobile account. State-changing.
    ClearAccount = 0x35,
    /// Configure the alarm password. State-changing.
    ConfigAlarmPwd = 0x38,
    /// Open the lock (enhanced, encrypted path). State-changing.
    OpenEnhance = 0x39,
    /// Register smart-key, get secret key. State-changing.
    RegSmartKey = 0x3E,
    /// Generate a temp secret key. State-changing.
    GenTempSecretKey = 0x3F,
    /// Toggle the WiFi status. State-changing.
    WifiToggle = 0x41,
    /// Verify the challenge MAC (part of the cipher auth). Not a state change
    /// by itself, but an auth step that only belongs in the cipher path.
    VerifyChallengeMac = 0x62,
    /// Toggle open-log upload. State-changing.
    OpenlogToggle = 0xF9,
}

impl Cmd {
    /// The on-air command byte — the variant's own value.
    pub fn byte(self) -> u8 {
        self as u8
    }

    /// Readable name for the log.
    pub fn name(self) -> &'static str {
        use Cmd::*;
        match self {
            GetSoftwareVersion => "get-version",
            GetSecretKey => "get-secret-key",
            GetSeid => "get-seid",
            GetChallenge => "get-challenge",
            OpenBasic => "open-basic",
            SyncTime => "sync-time",
            AddFinger => "add-finger",
            AddMobileAccount => "add-mobile-account",
            AddSmartKeyAuth => "add-smartkey-auth",
            DelFinger => "del-finger",
            DelMobileAccount => "del-mobile-account",
            DelSmartKey => "del-smartkey",
            UpdFingerAttr => "upd-finger-attr",
            UpdOpenPwd => "upd-open-pwd",
            Register => "register",
            ClearAccount => "clear-account",
            ConfigAlarmPwd => "config-alarm-pwd",
            OpenEnhance => "open-enhance",
            RegSmartKey => "reg-smartkey",
            GenTempSecretKey => "gen-temp-secretkey",
            WifiToggle => "wifi-toggle",
            VerifyChallengeMac => "verify-challenge-mac",
            OpenlogToggle => "openlog-toggle",
        }
    }

    /// Whether issuing this command changes device state.
    pub fn mutating(self) -> bool {
        use Cmd::*;
        !matches!(self, GetSoftwareVersion | GetSecretKey | GetSeid | GetChallenge)
    }

    /// The safe, read-only commands — always probed (never change state).
    pub const SAFE: [Cmd; 4] = [
        Cmd::GetSoftwareVersion,
        Cmd::GetSecretKey,
        Cmd::GetSeid,
        Cmd::GetChallenge,
    ];

    /// The state-changing commands — only probed on a cipher-capable lock
    /// (where they cannot succeed without the sekey MAC), never on a plaintext
    /// one. The open commands lead, so a misdetected lock is visible first.
    pub const MUTATING: [Cmd; 19] = [
        Cmd::OpenBasic,
        Cmd::OpenEnhance,
        Cmd::UpdOpenPwd,
        Cmd::SyncTime,
        Cmd::AddFinger,
        Cmd::AddMobileAccount,
        Cmd::AddSmartKeyAuth,
        Cmd::DelFinger,
        Cmd::DelMobileAccount,
        Cmd::DelSmartKey,
        Cmd::UpdFingerAttr,
        Cmd::Register,
        Cmd::ClearAccount,
        Cmd::ConfigAlarmPwd,
        Cmd::RegSmartKey,
        Cmd::GenTempSecretKey,
        Cmd::WifiToggle,
        Cmd::VerifyChallengeMac,
        Cmd::OpenlogToggle,
    ];
}

/// Send state-changing commands on a cipher-capable lock? They will fail without
/// the sekey MAC (mapping the response surface, not changing state), but
/// `0x03`/`0x39` are the open command — keep this OFF unless you are prepared for
/// the lock to open on a misdetected lock.
pub(crate) const PROBE_MUTATING: bool = false;

/// Build a DESSMANN command frame. Checksum = unsigned sum of `bytes[1..len-3]`
/// (big-endian), mirroring the SDK's `CRCUtil.a`.
pub fn build_cmd(cmd: Cmd, payload: &[u8]) -> Vec<u8, 20> {
    let mut f: Vec<u8, 20> = Vec::new();
    let _ = f.push(0xFE);
    let _ = f.push(0x01);
    let _ = f.push(cmd.byte());
    let _ = f.push((payload.len() >> 8) as u8);
    let _ = f.push(payload.len() as u8);
    let _ = f.extend_from_slice(payload);
    let n = f.len();
    let mut sum: u16 = 0;
    for &b in &f[1..n.saturating_sub(2)] {
        sum += b as u16;
    }
    let _ = f.push((sum >> 8) as u8);
    let _ = f.push((sum & 0xFF) as u8);
    f
}

/// Is this a DESSMANN 16-bit service UUID (the command channel's two services)?
pub fn is_dessmann_service(u16: Option<u16>) -> bool {
    matches!(u16, Some(0xFFE0 | 0xFFE5))
}

/// Detect a DESSMANN lock from its advertisement alone: the lock names itself
/// from its MAC with a `LOCK_` prefix (e.g. `LOCK_db05` from `…:0A:DB:05`).
pub fn is_dessmann_advert(ad: &[u8]) -> bool {
    adv_name(ad).is_some_and(|n| n.starts_with(b"LOCK_"))
}

/// The Name AD (0x09) bytes from an advertising payload, when present.
pub fn adv_name(ad: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    while i + 1 < ad.len() {
        let flen = ad[i] as usize;
        if flen == 0 || i + 1 + flen > ad.len() {
            break;
        }
        if ad[i + 1] == 0x09 {
            return Some(&ad[i + 2..i + 1 + flen]);
        }
        i += 1 + flen;
    }
    None
}

/// The DESSMANN service role of a characteristic UUID: `0xFFE9` = write (TX),
/// `0xFFE4` = notify (RX).
pub fn char_role(uuid16: Option<u16>) -> Option<Role> {
    match uuid16 {
        Some(0xFFE9) => Some(Role::Write),
        Some(0xFFE4) => Some(Role::Notify),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Write,
    Notify,
}
