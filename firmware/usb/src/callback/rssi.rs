//! RSSI-monitor mode setup callback (usb): a spectrum sweep rendered to a WS2812
//! strip (SPI on P1.11) plus the onboard RGB LED. No QSPI and no capture sink, so
//! the `setup` future is empty — the mode holds the SPI + PWM and drives both inline.

use embassy_nrf::spim::Spim;
use embassy_nrf::{Peri, peripherals};

use sonde_common::led::OnBoardLed as _;
use sonde_common::mode::{self, Mode as _};
use sonde_common::{led, ulog};

use crate::{CTX, ConsoleSink, LedParts};

#[embassy_executor::task]
pub async fn run(
    spi: Peri<'static, peripherals::SPI3>,
    din: Peri<'static, peripherals::P1_11>,
    l: LedParts,
) {
    ulog!("mode=rssi_monitor\r\n");
    let spi: Spim<'static> = crate::ws2812_spi(spi, din);

    // Checkpoint: SPI up — green blink so a bring-up hang is visible without a serial
    // monitor. Pins stolen and released for the mode's own LED below.
    let mut dbg = unsafe { led::Gpio::steal() };
    dbg.set(led::GREEN);
    cortex_m::asm::delay(3_000_000);
    dbg.set(led::OFF);
    drop(dbg);
    ulog!("spi_ok\r\n");

    let pwm = led::Pwm::new(l.pwm, l.r, l.g, l.b);
    let mut m = mode::RssiMonitor::<ConsoleSink>::new(spi, pwm);
    m.init(&CTX, async {}).await;
    m.run(&CTX).await
}
