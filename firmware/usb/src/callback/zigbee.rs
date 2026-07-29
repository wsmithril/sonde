//! Zigbee-sniff mode setup callback (usb): an IEEE 802.15.4 survey. No QSPI — the
//! provisioned tables are BT SIG company IDs and BLE UUIDs, and nothing in an
//! 802.15.4 MAC header resolves against them. The radio is reconfigured for 802.15.4
//! in the mode's `init`; the LED is driven inline, and the `setup` future spawns the
//! decode task that drains the queue.

use embassy_executor::Spawner;

use sonde_common::mode::{self, Mode as _};
use sonde_common::{led, ulog};

use crate::{CTX, ConsoleSink, LedParts};

#[embassy_executor::task]
pub async fn run(spawner: Spawner, l: LedParts) {
    ulog!("mode=zb_sniff\r\n");
    let leds = led::Gpio::new(l.r, l.g, l.b);
    let mut m = mode::ZigbeeSniff::<ConsoleSink>::new(leds);
    m.init(&CTX, async move {
        spawner.spawn(mode::zigbee::log_task().unwrap());
    })
    .await;
    m.run(&CTX).await
}
