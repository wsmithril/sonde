//! GATT-enum mode setup callback (headless): decodes to text → LOG → SD. The
//! `setup` future spawns the state-colour LED and the `text_to_ring` consumer.

use embassy_executor::Spawner;

use sonde_common::mode::{self as capmode, Mode as _};
use sonde_common::{LOG, led};

use crate::{CTX, LedParts, PcapSink, SD_RING};

/// Drain the log channel (GATT text decode) into the SD ring.
#[embassy_executor::task]
async fn text_to_ring() -> ! {
    loop {
        let (_t, line) = LOG.receive().await;
        SD_RING.push(line.as_bytes());
    }
}

#[embassy_executor::task]
pub async fn run(spawner: Spawner, l: LedParts) {
    let mut m = capmode::GattEnum::<PcapSink>::new();
    m.init(&CTX, async move {
        let pwm = led::Pwm::new(l.pwm, l.r, l.g, l.b);
        spawner.spawn(capmode::gatt::led_task(pwm).unwrap());
        spawner.spawn(text_to_ring().unwrap());
    })
    .await;
    m.run(&CTX).await
}
