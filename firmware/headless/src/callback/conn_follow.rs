//! Conn-follow mode setup callback (headless): the follower drives the RGB Gpio
//! inline per event; the `setup` future spawns `conn_to_ring`, which PCAP-encodes
//! the captured PDUs to SD.

use embassy_executor::Spawner;

use sonde_common::led;
use sonde_common::mode::{self as capmode, Mode as _};

use crate::storage::pcap;
use crate::{CTX, LedParts, PcapSink, SD_RING};

/// Drain the conn-follow queue, PCAP-encoding each captured PDU into the SD ring.
#[embassy_executor::task]
async fn conn_to_ring() -> ! {
    SD_RING.push(&pcap::global_header());
    let mut rec = [0u8; pcap::MAX_RECORD];
    loop {
        let p = capmode::conn_follow::RX_QUEUE.receive().await;
        // TODO(bench): plumb the connection AA/channel/RSSI from conn_follow's
        // follow state (RxPdu carries none); 0/0/0 are placeholders.
        let n = pcap::record(&mut rec, p.t_air.as_micros(), 0, 0, p.crc_ok, 0, &p.data[..p.len as usize]);
        SD_RING.push(&rec[..n]);
    }
}

#[embassy_executor::task]
pub async fn run(spawner: Spawner, l: LedParts) {
    let leds = led::Gpio::new(l.r, l.g, l.b);
    let mut m = capmode::ConnFollow::<PcapSink>::new(leds);
    m.init(&CTX, async move {
        spawner.spawn(conn_to_ring().unwrap());
    })
    .await;
    m.run(&CTX).await
}
