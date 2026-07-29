//! Opportunistic wall-clock: a device-wide UTC anchor learned from a peer's
//! Bluetooth Current Time Service (GATT mode, see `gatt::read_value`).
//!
//! Every firmware timestamp is an embassy `Instant` — microseconds since boot,
//! with no notion of the calendar. When the GATT central reads a peer's Current
//! Time characteristic and it decodes to a plausible date, [`anchor`] records
//! the offset between that peer's UTC and our monotonic clock; from then on
//! [`write_prefix`] renders every log line's timestamp as ISO-8601 UTC instead
//! of raw uptime. The anchor is RAM-only and reset by a reboot (relearned on the
//! next Current Time read); there is no battery-backed RTC.

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use embassy_time::Instant;

/// Unix-epoch seconds (from 1970-01-01 UTC) to the instant this device booted,
/// i.e. `wall_epoch - uptime` at the moment of the anchoring read; later reads
/// only add uptime. A `u32` reaches year 2106, so no 64-bit atomic (not
/// lock-free on this core) is needed. Meaningful only while `EPOCH_VALID` is set.
static BOOT_EPOCH_SECS: AtomicU32 = AtomicU32::new(0);
static EPOCH_VALID: AtomicBool = AtomicBool::new(false);

/// Record the wall-clock anchor from a decoded Current Time value: `wall_epoch`
/// is UTC seconds and `uptime` is the monotonic instant it was observed. The
/// sub-second phase of `uptime` is dropped, so the anchor carries up to ~1 s of
/// jitter — fine for dating logs, not a disciplined clock.
pub fn anchor(wall_epoch: u32, uptime: Instant) {
    let boot = wall_epoch.saturating_sub(uptime.as_secs() as u32);
    BOOT_EPOCH_SECS.store(boot, Ordering::Relaxed);
    EPOCH_VALID.store(true, Ordering::Relaxed);
}

/// The boot epoch (Unix seconds at boot) once a Current Time read has anchored
/// it, else `None`.
pub fn boot_epoch() -> Option<u32> {
    EPOCH_VALID
        .load(Ordering::Relaxed)
        .then(|| BOOT_EPOCH_SECS.load(Ordering::Relaxed))
}

/// Write a log-line timestamp prefix for a line queued at `queued_at`. Once the
/// wall-clock is anchored this is `[YYYY-MM-DDThh:mm:ss.mmmZ] `; before that it
/// falls back to the uptime form `[SSSSSS.mmm] `.
pub fn write_prefix(out: &mut impl Write, queued_at: Instant) {
    let ms = queued_at.as_millis();
    match boot_epoch() {
        Some(boot) => {
            let (y, mo, d, h, mi, s) = from_epoch(boot + (ms / 1000) as u32);
            let _ = write!(
                out,
                "[{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z] ",
                y, mo, d, h, mi, s, ms % 1000
            );
        }
        None => {
            let _ = write!(out, "[{}.{:03}] ", ms / 1000, ms % 1000);
        }
    }
}

/// Broken-down UTC date/time → Unix epoch seconds, via Howard Hinnant's
/// `days_from_civil`. Callers gate `year` to 2000..=2100, so the `u32` result
/// never overflows.
pub fn to_epoch(year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8) -> u32 {
    // Shift so the leap day falls at the end of the (shifted) year.
    let y = year as i32 - if month <= 2 { 1 } else { 0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as u32; // year of era, [0, 399]
    let m = month as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as u32 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day of era, [0, 146096]
    let days = era * 146097 + doe as i32 - 719468; // days since 1970-01-01
    days as u32 * 86400 + hour as u32 * 3600 + min as u32 * 60 + sec as u32
}

/// Unix epoch seconds → broken-down UTC date/time — the inverse of [`to_epoch`],
/// via Hinnant's `civil_from_days`.
pub fn from_epoch(secs: u32) -> (u16, u8, u8, u8, u8, u8) {
    let days = (secs / 86400) as i32;
    let rem = secs % 86400;
    let hour = (rem / 3600) as u8;
    let min = ((rem % 3600) / 60) as u8;
    let sec = (rem % 60) as u8;

    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // month, shifted so March = 0, [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8; // [1, 12]
    let year = (y + if month <= 2 { 1 } else { 0 }) as u16;
    (year, month, day, hour, min, sec)
}
