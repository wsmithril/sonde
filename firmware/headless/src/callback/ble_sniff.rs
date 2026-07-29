//! BLE-sniff mode setup callback (headless): radio producer + PCAP-to-SD consumer
//! (via the sink). The `setup` future spawns the rate/liveness LED; SD is on P1.x,
//! so the RGB pins are free.

use embassy_executor::Spawner;

use sonde_common::led;
use sonde_common::mode::{self as capmode, Mode as _};

use crate::{CTX, LedParts, PcapSink};

#[embassy_executor::task]
pub async fn run(spawner: Spawner, l: LedParts) {
    let mut m = capmode::BleSniff::<PcapSink>::new();
    m.init(&CTX, async move {
        let pwm = led::Pwm::new(l.pwm, l.r, l.g, l.b);
        spawner.spawn(capmode::ble_sniff::led_task(pwm).unwrap());
    })
    .await;
    m.run(&CTX).await
}
