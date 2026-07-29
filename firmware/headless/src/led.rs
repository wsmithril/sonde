//! Mono LED backend (nice!nano v2): the whole indication scheme for the headless
//! build is one LED — blink the boot-mode ordinal at startup, then a 1 ms flash on
//! every captured packet, in every mode. The per-mode colour semantics of the USB
//! build do not apply here, so the capture code drives no LED (it passes
//! `sonde_common::led::Noop`); the flashes come from the queue consumers via
//! [`flash`], decoupled from the mode logic.

use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::peripherals::P0_15;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::Timer;

// nice!nano onboard LED is active-LOW: driving the pin low lights it. CONFIRM the
// pin (P0.15 stock) and polarity against the specific clone.
const ON: Level = Level::Low;
const DARK: Level = Level::High;

/// Fired once per captured packet by the queue consumers. One slot, so a burst of
/// packets inside a single flash coalesces to one pending flash rather than a
/// backlog — the LED reports "the air is live", the log carries the count.
static FLASH: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Signal a captured packet — the LED task renders a 1 ms flash.
pub fn flash() {
    FLASH.signal(());
}

/// The onboard LED task: blink `blinks` times at boot (the mode indicator), then a
/// 1 ms flash on every [`flash`] for the life of the run.
#[embassy_executor::task]
pub async fn task(mut led: Output<'static>, blinks: u8) -> ! {
    for _ in 0..blinks {
        led.set_level(ON);
        Timer::after_millis(200).await;
        led.set_level(DARK);
        Timer::after_millis(200).await;
    }
    led.set_level(DARK);
    loop {
        FLASH.wait().await;
        led.set_level(ON);
        Timer::after_millis(1).await;
        led.set_level(DARK);
    }
}

/// Steal the LED pin and blink it forever — the no-SD-card fatal indication, shown
/// before the LED task has taken the pin.
pub fn fatal_blink() -> ! {
    let mut led = Output::new(unsafe { P0_15::steal() }, DARK, OutputDrive::Standard);
    loop {
        led.set_level(ON);
        cortex_m::asm::delay(8_000_000);
        led.set_level(DARK);
        cortex_m::asm::delay(8_000_000);
    }
}
