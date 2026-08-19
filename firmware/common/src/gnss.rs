//! DX-GP21-A GNSS module integration, on the migrated `dx-gp21-nrf52840` board
//! layer (Embassy edition, sibling repo `../dx-gp21-rust`).
//!
//! XIAO nRF52840 header pins (all free in the sonde build):
//! ```text
//!   A0 (P0.02) → module R (UART TX to the module)        UARTE0 TXD
//!   A1 (P0.03) ← module T (UART RX — NMEA sentences)     UARTE0 RXD
//!   A2 (P0.04) ← module P (1PPS, rising edge 1 Hz after fix)  GPIOTE PORT event
//!   A3 (P0.05) → module W (power: onboard pull-up → float/HIGH = on, LOW = off)
//! ```
//!
//! Boot check: [`spawn`] powers the module on, then waits up to [`PROBE_MS`] for
//! a first NMEA line on the UART; only if the module answers does it hand the
//! UART to [`DxGp21GnssModule`] and spawn its feed + 1PPS tasks. A missing module
//! leaves the 1PPS pin unbound — a floating input must not drive the pulse
//! handler.
//!
//! The caller-owned GNSS state lives in [`GNSS_STATE`]. The crate's 1PPS task
//! wakes on each rising edge (the module's exact-second mark) and calls
//! [`gnss_pps`], which anchors the log wall-clock to GPS UTC on the first dated
//! fix and logs the stored location.
#![allow(dead_code)]

use core::cell::RefCell;

use critical_section::Mutex;
use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
use embassy_nrf::uarte::{self, UarteRx};
use embassy_time::{Duration, Instant, Timer, with_timeout};

use dx_gp21_nrf52840::{DxGp21GnssModule, FixSnapshot, GnssState};

/// How long to wait at boot for the module's first NMEA line before declaring it
/// absent (and skipping the 1PPS registration).
const PROBE_MS: u64 = 2000;
/// Module power-ON settle before probing.
const POWER_SETTLE_MS: u64 = 300;

/// Caller-owned GNSS state, shared by the crate's feed task (writer) and the
/// 1PPS task (reader via the [`FixSnapshot`] callback).
static GNSS_STATE: Mutex<RefCell<GnssState<64>>> = Mutex::new(RefCell::new(GnssState::new()));

/// Wire the GNSS module and spawn its tasks. Returns `true` if the module
/// answered the probe (and the 1PPS task is running); `false` if absent (the
/// 1PPS pin is left unbound).
#[allow(clippy::too_many_arguments)]
pub async fn spawn(
    spawner: embassy_executor::Spawner,
    uarte: embassy_nrf::Peri<'static, embassy_nrf::peripherals::UARTE0>,
    irq: impl embassy_nrf::interrupt::typelevel::Binding<
        <embassy_nrf::peripherals::UARTE0 as embassy_nrf::uarte::Instance>::Interrupt,
        uarte::InterruptHandler<embassy_nrf::peripherals::UARTE0>,
    > + 'static,
    tx_pin: embassy_nrf::Peri<'static, embassy_nrf::peripherals::P0_02>,
    rx_pin: embassy_nrf::Peri<'static, embassy_nrf::peripherals::P0_03>,
    pps_pin: embassy_nrf::Peri<'static, embassy_nrf::peripherals::P0_04>,
    power_pin: embassy_nrf::Peri<'static, embassy_nrf::peripherals::P0_05>,
) -> bool {
    // Power the module on: W floats high (pull-up) → drive HIGH explicitly.
    let power = Output::new(power_pin, Level::High, OutputDrive::Standard);
    Timer::after(Duration::from_millis(POWER_SETTLE_MS)).await;

    // Build the UART ourselves so we can probe it before handing it over.
    let mut config = uarte::Config::default();
    config.baudrate = uarte::Baudrate::Baud115200;
    let mut uart = uarte::Uarte::new(uarte, rx_pin, tx_pin, irq, config);

    // Probe: does the module answer on the UART within PROBE_MS?
    let (_, rx) = uart.split_by_ref();
    if !probe(rx, Duration::from_millis(PROBE_MS)).await {
        ulogf!("gnss: no module on the UART — 1PPS left unbound\r\n");
        drop(uart);
        drop(power);
        return false;
    }
    ulogf!("gnss: module present — starting NMEA feed + 1PPS\r\n");

    // Hand the UART to the board layer, which spawns its feed + 1PPS tasks.
    let module = DxGp21GnssModule::from_uart(
        uart,
        Some(power),
        Some(Input::new(pps_pin, Pull::Down)),
        &GNSS_STATE,
    );
    match module.spawn(spawner, gnss_pps) {
        Ok(()) => {}
        Err(e) => ulogf!("gnss: task spawn failed ({:?})\r\n", e),
    }
    true
}

/// Read from the UART for up to `timeout`; any bytes mean the module is talking.
///
/// `UarteRx::read` blocks until the buffer fills, so it is wrapped in
/// [`with_timeout`] — a missing module (no data, no error) must not hang boot.
async fn probe(rx: &mut UarteRx<'static>, timeout: Duration) -> bool {
    let mut buf = [0u8; 16];
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        match with_timeout(deadline.saturating_duration_since(now), rx.read(&mut buf)).await {
            // A successful read with any non-zero byte = the module talking.
            Ok(Ok(())) if !buf.iter().all(|&b| b == 0) => return true,
            Ok(Ok(())) => buf.fill(0),
            Ok(Err(_)) => return false,
            Err(_) => {} // read timed out — keep probing until the deadline
        }
    }
}

/// 1PPS callback: the board layer wakes this once per second (the module's
/// exact-second mark) with a [`FixSnapshot`] of the shared state.
///
/// Anchors the log wall-clock to GPS UTC on the first dated RMC fix — after
/// this, `wallclock::write_prefix` renders every log line as ISO-8601 UTC
/// instead of boot uptime — then logs the stored location.
fn gnss_pps(snap: FixSnapshot) {
    // Anchor once: the RMC date + time carried on the first pulse after a fix.
    if let (Some(date), Some(time)) = (snap.utc_date, snap.utc_time)
        && crate::wallclock::boot_epoch().is_none()
    {
        let epoch = to_epoch(
            date.year as u32,
            date.month as u32,
            date.day as u32,
            time.hour as u32,
            time.minute as u32,
            time.second as u32,
        );
        crate::wallclock::anchor(epoch, Instant::now());
        ulogf!("gnss: log timestamps anchored to GPS UTC (epoch {})\r\n", epoch);
    }
    match (snap.lat, snap.lon) {
        (Some(lat), Some(lng)) => {
            let t = snap.utc_time.unwrap_or_default();
            let lat_e7 = (lat * 1e7) as i32;
            let lng_e7 = (lng * 1e7) as i32;
            ulogf!(
                "gnss 1PPS: {:02}:{:02}:{:02} fix {}.{:07}, {}.{:07}\r\n",
                t.hour,
                t.minute,
                t.second,
                lat_e7 / 10_000_000,
                lat_e7.abs() % 10_000_000,
                lng_e7 / 10_000_000,
                lng_e7.abs() % 10_000_000,
            );
        }
        _ => ulogf!("gnss 1PPS: pulse, no fix yet\r\n"),
    }
}

/// Days-from-civil / seconds-from-epoch (Howard Hinnant), for the GPS UTC date +
/// time → Unix-epoch conversion the wallclock anchor needs.
fn to_epoch(y: u32, m: u32, d: u32, h: u32, mi: u32, s: u32) -> u32 {
    let (y, m, d, h, mi, s) = (y as i64, m as i64, d as i64, h as i64, mi as i64, s as i64);
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468; // days since 1970-01-01
    (days * 86_400 + h * 3_600 + mi * 60 + s) as u32
}
