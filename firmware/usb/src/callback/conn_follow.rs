//! Conn-follow mode setup callback (usb). The follower owns the RGB LED as a `Gpio`
//! and toggles it inline per radio event (no separate indicator task). The `setup`
//! future maps the QSPI asset window (so LL_VERSION_IND company IDs / ATT UUIDs
//! resolve to names) and spawns the decode task that drains the capture queue.

use embassy_executor::Spawner;

use sonde_common::mode::{self, Mode as _};
use sonde_common::{led, ulog};

use crate::{CTX, ConsoleSink, LedParts, QspiParts};

#[embassy_executor::task]
pub async fn run(spawner: Spawner, q: QspiParts, l: LedParts) {
    ulog!("mode=conn_follow\r\n");
    let leds = led::Gpio::new(l.r, l.g, l.b);
    let mut m = mode::ConnFollow::<ConsoleSink>::new(leds);
    m.init(&CTX, async move {
        crate::hold_assets(spawner, crate::qspi_setup(q));
        spawner.spawn(mode::conn_follow::log_task().unwrap());
    })
    .await;
    m.run(&CTX).await
}
