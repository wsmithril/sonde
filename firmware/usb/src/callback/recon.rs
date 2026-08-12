//! Reconnaissance setup callback (usb): map the QSPI asset window (so UUID lookups
//! resolve names during enumeration) and spawn the recon mode — one main loop
//! (scan → classify → per-kind survey/assessment/report) plus the phase-colour LED.
//! Nothing here needs the capture sink.

use embassy_executor::Spawner;

use sonde_common::mode::recon;
use sonde_common::{led, ulog};

use crate::{LedParts, QspiParts};

#[embassy_executor::task]
pub async fn run(spawner: Spawner, q: QspiParts, l: LedParts) {
    ulog!("mode=recon\r\n");
    crate::hold_assets(spawner, crate::qspi_setup(q));

    let pwm = led::Pwm::new(l.pwm, l.r, l.g, l.b);
    spawner.spawn(recon::led_task(pwm).unwrap());
    spawner.spawn(recon::run().unwrap());
}
