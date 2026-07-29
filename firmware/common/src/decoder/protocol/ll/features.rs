//! The 8-octet Link Layer FeatureSet (Core v5.4 Vol 6 Part B §4.6).
//!
//! Carried by `LL_FEATURE_REQ`, `LL_FEATURE_RSP` and
//! `LL_PERIPHERAL_FEATURE_REQ`. Each bit is one feature, numbered from the LSB
//! of octet 0, and a peer advertises what it supports rather than what it
//! intends to use — so this is a capability list, not a description of the
//! link.

/// Short label for FeatureSet bit `n`, or `None` for bits this table predates.
///
/// The names are shortened from the spec's prose ("DataLenExt" for "LE Data
/// Packet Length Extension") to keep a fully-featured peer's list to a few
/// lines. Bits without an entry print as `bit<n>`: the raw octets are on the
/// line above, so an unnamed bit stays visible and countable, and a table that
/// has fallen behind the spec never invents a label.
const fn name(n: u8) -> Option<&'static str> {
    Some(match n {
        0 => "Encryption",
        1 => "ConnParamReq",
        2 => "ExtReject",
        3 => "PeriphFeatExch",
        4 => "Ping",
        5 => "DataLenExt",
        6 => "LLPrivacy",
        7 => "ExtScanFilter",
        8 => "2M-PHY",
        9 => "StableModIdx-Tx",
        10 => "StableModIdx-Rx",
        11 => "Coded-PHY",
        12 => "ExtAdv",
        13 => "PeriodicAdv",
        14 => "CSA#2",
        15 => "PowerClass1",
        16 => "MinUsedChannels",
        17 => "ConnCTE-Req",
        18 => "ConnCTE-Rsp",
        19 => "ConnlessCTE-Tx",
        20 => "ConnlessCTE-Rx",
        21 => "AntSwitch-AoD",
        22 => "AntSwitch-AoA",
        23 => "CTE-Rx",
        24 => "PAST-Sender",
        25 => "PAST-Recipient",
        26 => "SCA-Updates",
        27 => "RemotePubKeyValidation",
        28 => "CIS-Central",
        29 => "CIS-Peripheral",
        30 => "ISO-Broadcaster",
        31 => "SyncReceiver",
        32 => "CIS-HostSupport",
        // The spec assigns the same name to 33 and 34; both are listed so the
        // bit index in the log still maps one-to-one onto the spec table.
        33 => "PowerControlReq",
        34 => "PowerControlReq",
        35 => "PathLossMonitoring",
        36 => "PeriodicAdvADI",
        37 => "ConnSubrating",
        38 => "ConnSubrating-Host",
        39 => "ChannelClassification",
        40 => "AdvCodingSelection",
        41 => "AdvCodingSelection-Host",
        _ => return None,
    })
}

/// Emit the raw octets followed by the names of every set bit, wrapped.
///
/// `p` is the FeatureSet as it appears on air, LSB-first. A current phone sets
/// around thirty bits, so the list is wrapped at [`WRAP`] characters rather than
/// run onto one very long line.
pub(super) fn emit(p: &[u8]) {
    use core::fmt::Write;

    /// Wrap width for the name list, chosen to sit inside an 80-column terminal
    /// once the continuation indent is added.
    const WRAP: usize = 72;

    let mut raw = crate::LogLine::new();
    let _ = raw.push_str("      features=");
    for b in p {
        let _ = write!(raw, "{:02X}", b);
    }
    crate::terminate_line(&mut raw);
    crate::log_send(raw);

    let mut line = crate::LogLine::new();
    let _ = line.push_str("    ");
    let mut empty = true;
    for (i, b) in p.iter().enumerate() {
        for bit in 0..8u8 {
            if b & (1 << bit) == 0 {
                continue;
            }
            let n = i as u8 * 8 + bit;
            let mut item = heapless::String::<32>::new();
            match name(n) {
                Some(s) => {
                    let _ = item.push_str(s);
                }
                None => {
                    let _ = write!(item, "bit{}", n);
                }
            }
            if !empty && line.len() + 1 + item.len() > WRAP {
                crate::terminate_line(&mut line);
                crate::log_send(line);
                line = crate::LogLine::new();
                let _ = line.push_str("        ");
                empty = true;
            }
            if !empty {
                let _ = line.push(' ');
            }
            let _ = line.push_str(&item);
            empty = false;
        }
    }
    if !empty {
        crate::terminate_line(&mut line);
        crate::log_send(line);
    }
}
