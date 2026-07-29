//! Midea-control setup callback (usb): map the QSPI asset window (so UUID lookups
//! resolve names during enumeration) and spawn the Midea task fleet — one discovery
//! scanner, one handshake worker, a 4-wide probe pool, and the state-colour LED.
//! The tasks share one radio via `midea`'s internal mutex and an in-memory device
//! table; nothing here needs the capture sink.

use embassy_executor::Spawner;

use sonde_common::mode::midea;
use sonde_common::{led, ulog};

use crate::{LedParts, QspiParts};

#[embassy_executor::task]
pub async fn run(spawner: Spawner, q: QspiParts, l: LedParts) {
    ulog!("mode=midea_ctl\r\n");
    crate::hold_assets(spawner, crate::qspi_setup(q));

    let pwm = led::Pwm::new(l.pwm, l.r, l.g, l.b);
    spawner.spawn(midea::led_task(pwm).unwrap());
    spawner.spawn(midea::scan_task().unwrap());
    spawner.spawn(midea::handshake_task().unwrap());
    for _ in 0..4 {
        spawner.spawn(midea::probe_task().unwrap());
    }
}
