//! Boot-time mode cycle, shared by every firmware build.
//!
//! The probe runs one of five mutually-exclusive modes, cycled on each reset so
//! it can be switched without reflashing:
//!   • BLE sniff    — advertising scan + GPIO packet-colour LED indicator.
//!   • RSSI monitor — spectrum sweep to the WS2812 strip + onboard RGB average.
//!   • GATT enum    — active central: connect to a peripheral and walk its GATT.
//!   • Conn follow  — passive: catch a CONNECT_IND and follow the connection.
//!   • Zigbee sniff — IEEE 802.15.4 survey: energy sweep + MAC-header capture.
//!
//! Zigbee is mutually exclusive with the rest for a hardware reason: one RADIO
//! and one MODE register, and 802.15.4 needs different modulation/sync/CRC/
//! whitening than BLE, so the two cannot be interleaved within a run.
//!
//! State is persisted in a reserved 4 KB flash page, NOT in RAM/GPREGRET: the
//! XIAO's UF2 bootloader runs on every reset with its stack at the top of RAM and
//! clobbers any retained-RAM cell (and it doesn't preserve GPREGRET), so every RAM
//! scheme read back "cold" and the mode never flipped. Flash survives the
//! bootloader (and power loss). Each boot appends the new mode to the next free
//! 4-byte slot — one word write, no erase — so the page is erased only once per
//! ~1024 reboots. Every reset advances the mode mod [`BOOT_MODES`].

use embassy_nrf::nvmc::Nvmc;
use embassy_nrf::{Peri, peripherals};

#[derive(Clone, Copy)]
pub enum BootMode {
    BleSniff,
    RssiMonitor,
    GattEnum,
    ConnFollow,
    ZigbeeSniff,
}

pub const BOOT_MODES: u32 = 5;

// Reserved boot-mode page: the last 4 KB of internal flash carved off in memory.x
// (which now ends at 0xEC000). Must equal that region's end so the flasher, which
// only writes the app region below it, never rewrites the stored mode.
const BOOT_MODE_PAGE: u32 = 0x000E_C000;
const BOOT_MODE_PAGE_LEN: u32 = embassy_nrf::nvmc::PAGE_SIZE as u32; // 4096
// Slot encoding: high 24 bits are a tag marking a written slot; low byte is the
// mode (0..4). Erased flash reads 0xFFFFFFFF, which fails the tag test = "free".
const SLOT_TAG: u32 = 0x0DE0_0000;
const SLOT_TAG_MASK: u32 = 0xFFFF_FF00;

/// Advance and persist the boot mode in the reserved flash page, returning this
/// boot's mode. The SoftDevice is present in flash but never enabled (we drive the
/// RADIO directly), so NVMC writes are safe without SD flash calls.
pub fn next_boot_mode(nvmc: Peri<'static, peripherals::NVMC>) -> BootMode {
    use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};

    let mut flash = Nvmc::new(nvmc);
    let base = BOOT_MODE_PAGE;
    let slots = (BOOT_MODE_PAGE_LEN / 4) as usize;

    // Walk the append log: `prev` = last valid mode, `free` = first empty slot.
    // Any unrecognised word (stale bytes from a prior larger build, or a torn
    // write) is treated as corruption → wipe the page and restart the log.
    let mut prev: Option<u32> = None;
    let mut free: Option<usize> = None;
    let mut corrupt = false;
    for i in 0..slots {
        let mut b = [0u8; 4];
        if flash.read(base + (i as u32) * 4, &mut b).is_err() {
            corrupt = true;
            break;
        }
        let w = u32::from_le_bytes(b);
        if w == 0xFFFF_FFFF {
            free = Some(i);
            break;
        } else if (w & SLOT_TAG_MASK) == SLOT_TAG {
            prev = Some(w & 0xFF);
        } else {
            corrupt = true;
            break;
        }
    }

    let mut mode = match prev {
        Some(p) => (p + 1) % BOOT_MODES,
        None => 0,
    };
    // Temporarily skip RssiMonitor (1) and ZigbeeSniff (4): advance past a
    // blacklisted mode so the cycle visits only BleSniff/GattEnum/ConnFollow. The
    // resolved (non-blacklisted) mode is what gets persisted, so the next boot's
    // `(prev + 1)` continues from here. BleSniff (0) is never blacklisted, so the
    // loop always terminates.
    while matches!(mode, 1 | 4) {
        mode = (mode + 1) % BOOT_MODES;
    }
    let slot = match free {
        Some(f) if !corrupt => f,
        // page full or unrecognised contents → erase and start the log over
        _ => {
            let _ = flash.erase(base, base + BOOT_MODE_PAGE_LEN);
            0
        }
    };
    let _ = flash.write(base + (slot as u32) * 4, &(SLOT_TAG | mode).to_le_bytes());

    // Every arm is spelled out: a catch-all here silently aliases any mode added
    // past the last named one onto its neighbour, and the symptom — a reset that
    // appears to do nothing — looks like the flash log failing, not like this.
    match mode {
        0 => BootMode::BleSniff,
        1 => BootMode::RssiMonitor,
        2 => BootMode::GattEnum,
        3 => BootMode::ConnFollow,
        _ => BootMode::ZigbeeSniff,
    }
}

/// The clock configuration every build boots with — shared so the two firmwares
/// can never drift on timing (they share every radio anchor and hop deadline).
///
/// The nRF52840 RADIO requires HFCLK sourced from the external crystal (HFXO) to
/// receive/transmit or produce valid RSSI. With the default (`HfclkSource::Internal`)
/// the crystal never starts, so no ADV packet demodulates and RSSI reads the noise
/// floor on every channel. `embassy_nrf::init` then issues `TASKS_HFCLKSTART` and
/// blocks until `EVENTS_HFCLKSTARTED` before returning.
///
/// LFCLK is embassy-time's entire tick base, so it sets every connection anchor,
/// T_IFS deadline and hop instant in `gatt`/`conn_follow`. The default is
/// `InternalRC` — an uncalibrated RC oscillator, measurably ~3100 ppm slow here: a
/// locked follower re-anchoring every event saw a persistent -122 µs against a
/// 30 ms interval (~32666 Hz, not 32768). BLE allows 500 ppm total; radio bit
/// timing comes off HFCLK and was always fine, so the symptom was correct packets
/// on a wrong schedule. `Synthesized` divides the HFCLK we already source from the
/// crystal, inheriting HFXO accuracy, and always starts — `ExternalXtal` would spin
/// forever on `EVENTS_LFCLKSTARTED` on a board with no 32.768 kHz crystal. The cost
/// is HFCLK must keep running, irrelevant while the radio is on and USB-powered.
pub fn clock_config() -> embassy_nrf::config::Config {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    config.lfclk_source = embassy_nrf::config::LfclkSource::Synthesized;
    config
}

/// This boot mode's ordinal, 0-based — for a mono LED that blinks `index + 1`
/// times, or any other index-keyed indication.
pub fn mode_index(mode: BootMode) -> u8 {
    match mode {
        BootMode::BleSniff => 0,
        BootMode::RssiMonitor => 1,
        BootMode::GattEnum => 2,
        BootMode::ConnFollow => 3,
        BootMode::ZigbeeSniff => 4,
    }
}
