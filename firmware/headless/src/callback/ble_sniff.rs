//! BLE-sniff mode setup callback (headless): radio producer + PCAP-to-SD consumer
//! (via the sink). The `setup` future spawns the rate/liveness LED; SD is on P1.x,
//! so the RGB pins are free.

use embassy_executor::Spawner;

use sonde_common::hal::radio::BleCrcRepair;
use sonde_common::led;
use sonde_common::mode::{self as capmode, CaptureSink as _, Mode as _};

use crate::{CTX, LedParts, PcapSink};

/// Drain and encode queued packets independently of the radio producer, so SD
/// ring writes and optional CRC repair cannot delay DMA pointer rotation.
#[embassy_executor::task]
async fn decode_forever() -> ! {
    let mut crc_repair = BleCrcRepair::default();
    loop {
        let mut packet = capmode::ble_sniff::RX_QUEUE.receive().await;
        capmode::ble_sniff::repair_queued(&mut packet, &mut crc_repair);
        CTX.sink().sink_frame(&packet);
    }
}

pub async fn run(spawner: Spawner, l: LedParts) -> ! {
    let mut m = capmode::BleSniff::<PcapSink>::new();
    m.init(&CTX, async move {
        let pwm = led::Pwm::new(l.pwm, l.r, l.g, l.b);
        spawner.spawn(capmode::ble_sniff::led_task(pwm).unwrap());
        spawner.spawn(decode_forever().unwrap());
    })
    .await;
    m.run(&CTX).await
}
