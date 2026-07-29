#![no_std]
#![no_main]

//! Headless SD-capture build: captures raw PDUs to an SD card as PCAP (sniff,
//! conn-follow) or text (gatt), through a byte ring drained by an SD writer task.
//! While a host is connected it *also* exposes the card as a read-only FAT32 drive
//! over USB Mass Storage (only finalized runs are listed, so capture continues
//! safely). No deep decode, no QSPI.
//!
//! HARDWARE-UNVERIFIED: the SD driver, run index, and USB-MSC path are written to
//! spec but need bench bring-up (only the FAT32 layout was validated on a host).
//! One run is opened per boot; hourly sniff rotation, per-connection runs, and
//! conn-follow AA/channel/RSSI plumbing are marked TODO.

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::spim::{self, Spim};
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_nrf::usb::{self, Driver};
use embassy_nrf::{bind_interrupts, peripherals};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Timer};
use embassy_usb::{Builder, Config as UsbConfig, UsbDevice};
use static_cell::StaticCell;
use defmt_rtt as _;

use sonde_common::boot::{self, BootMode, next_boot_mode};
use sonde_common::{Rng, ble_sniff, common, conn_follow, gatt, panic};

mod led;
mod storage;
mod usb_msc;
use storage::pcap;
use storage::ring::Ring;
use storage::runidx::{Kind, Mode, PANIC_LBA, RunIndex, SUPERBLOCK_LBA};
use storage::sd::SdCard;
use usb_msc::UsbDriver;

bind_interrupts!(struct Irqs {
    SPI2        => spim::InterruptHandler<peripherals::SPI2>;
    USBD        => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => usb::vbus_detect::InterruptHandler;
});

/// Advertising access address — the reference AA in sniff PCAP records.
const ADV_AA: u32 = 0x8E89_BED6;

type SharedCard = Mutex<CriticalSectionRawMutex, SdCard<'static>>;
type SharedIndex = Mutex<CriticalSectionRawMutex, RunIndex>;

/// Byte ring between the capture/decode tasks and the SD writer.
static SD_RING: Ring<65536> = Ring::new();
static CARD: StaticCell<SharedCard> = StaticCell::new();
static INDEX: StaticCell<SharedIndex> = StaticCell::new();

// ── Consumers: capture queues / log → PCAP or text into the ring ────────────────

#[embassy_executor::task]
async fn sniff_to_ring() -> ! {
    SD_RING.push(&pcap::global_header());
    let mut rec = [0u8; pcap::MAX_RECORD];
    loop {
        let p = ble_sniff::RX_QUEUE.receive().await;
        led::flash();
        let n = pcap::record(
            &mut rec,
            p.t_air.as_micros(),
            p.ch,
            p.rssi_dbm as i8,
            p.crc_ok,
            ADV_AA,
            &p.data[..p.len as usize],
        );
        SD_RING.push(&rec[..n]);
    }
}

#[embassy_executor::task]
async fn conn_to_ring() -> ! {
    SD_RING.push(&pcap::global_header());
    let mut rec = [0u8; pcap::MAX_RECORD];
    loop {
        let p = conn_follow::RX_QUEUE.receive().await;
        led::flash();
        // TODO(bench): plumb the connection AA/channel/RSSI from conn_follow's
        // follow state (RxPdu carries none); 0/0/0 are placeholders.
        let n = pcap::record(&mut rec, p.t_air.as_micros(), 0, 0, p.crc_ok, 0, &p.data[..p.len as usize]);
        SD_RING.push(&rec[..n]);
    }
}

#[embassy_executor::task]
async fn text_to_ring() -> ! {
    loop {
        let (_t, line) = sonde_common::LOG.receive().await;
        led::flash();
        SD_RING.push(line.as_bytes());
    }
}

// ── Writer: ring → SD blocks for this boot's run ────────────────────────────────

#[embassy_executor::task]
async fn sd_writer(card: &'static SharedCard, index: &'static SharedIndex, run: usize, start_lba: u32) -> ! {
    let mut block = [0u8; 512];
    let mut fill = 0usize;
    let mut lba = start_lba;
    let mut written: u32 = 0;
    let mut since_flush: u32 = 0;
    loop {
        let got = SD_RING.read(&mut block[fill..]);
        fill += got;
        if fill < block.len() {
            Timer::after(Duration::from_millis(20)).await;
            continue;
        }
        {
            let mut c = card.lock().await;
            let _ = c.write_block(lba, &block).await;
        }
        lba += 1;
        written += block.len() as u32;
        since_flush += block.len() as u32;
        fill = 0;
        // Re-flush the (still unfinalized) run length ~every 64 KiB so a crash
        // loses at most that much; the run only becomes host-visible once a later
        // boot finalizes it. TODO(bench): finalize + rotate hourly for sniff.
        if since_flush >= 64 * 1024 {
            let sb = {
                let mut ix = index.lock().await;
                ix.set_len(run, written, false);
                ix.encode()
            };
            let mut c = card.lock().await;
            let _ = c.write_block(SUPERBLOCK_LBA, &sb).await;
            since_flush = 0;
        }
    }
}

// ── Capture drivers (same radio paths as the USB build) ─────────────────────────

#[embassy_executor::task]
async fn ble_task() -> ! {
    let mut rng = Rng(0x1234_5678);
    loop {
        ble_sniff::scan(&mut rng).await;
    }
}

#[embassy_executor::task]
async fn conn_follow_task() {
    // The mono LED flashes from the queue consumers, so the follower drives none.
    conn_follow::run(sonde_common::led::Noop).await;
}

#[embassy_executor::task]
async fn gatt_task() -> ! {
    let mut rng = Rng(0x1234_5678);
    loop {
        gatt::run(&mut rng).await;
    }
}

/// Persist any crash records from the previous boot to the dedicated panic block.
///
/// The block is append-only and never rolled into a run: successive crashes are
/// appended after the last entry (`[0..2]` = bytes used, `[2..]` = text). When the
/// next report will not fit, the whole block is cleared and the report written
/// fresh, so the newest crash always survives. The flash records are erased once
/// they are on the card.
async fn persist_panic(sd: &mut SdCard<'static>) {
    let mut text = [0u8; 480];
    let plen = panic::read_records_text(&mut text);
    if plen == 0 {
        return;
    }
    let mut blk = [0u8; 512];
    if sd.read_block(PANIC_LBA, &mut blk).await.is_err() {
        return; // can't read the block back → leave the flash record for next boot
    }
    let mut used = u16::from_le_bytes([blk[0], blk[1]]) as usize;
    const CAP: usize = 512 - 2; // text bytes after the 2-byte length header
    if used > CAP || used + plen > CAP {
        // Blank/corrupt header, or no room for the new entry → start the block over.
        used = 0;
        blk[2..].fill(0);
    }
    blk[2 + used..2 + used + plen].copy_from_slice(&text[..plen]);
    used += plen;
    blk[0..2].copy_from_slice(&(used as u16).to_le_bytes());
    if sd.write_block(PANIC_LBA, &blk).await.is_ok() {
        panic::clear(); // safely on the card now; wipe the flash records
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Clock setup is shared with the USB build — see `boot::clock_config`.
    let p = embassy_nrf::init(boot::clock_config());

    common::radio_configure_ble();
    // A prior boot's crash records are persisted to the SD panic block once the
    // card is up (see the storage block below) — there is no console to print to.

    let mode = next_boot_mode(p.NVMC);
    // Onboard mono LED: blinks the mode ordinal at boot, then a 1 ms flash per
    // captured packet (fed by the queue consumers). CONFIRM P0.15 on the board.
    let led_pin = Output::new(p.P0_15, Level::High, OutputDrive::Standard);
    spawner.spawn(led::task(led_pin, boot::mode_index(mode) + 1).unwrap());
    let capture = !matches!(mode, BootMode::RssiMonitor | BootMode::ZigbeeSniff);

    // Radio capture + ring consumers depend on neither the SD card nor USB, so
    // start them now; they fill SD_RING while the card comes up (the ring drops
    // and counts if the writer is not draining yet — a brief startup loss).
    if capture {
        match mode {
            BootMode::BleSniff => {
                spawner.spawn(sniff_to_ring().unwrap());
                spawner.spawn(ble_task().unwrap());
            }
            BootMode::GattEnum => {
                spawner.spawn(text_to_ring().unwrap());
                spawner.spawn(gatt_task().unwrap());
            }
            BootMode::ConnFollow => {
                spawner.spawn(conn_to_ring().unwrap());
                spawner.spawn(conn_follow_task().unwrap());
            }
            _ => {}
        }
    }

    // Build the USB device (construction is synchronous, no card dependency). Its
    // enumeration — `device.run()` — is async and runs in the join below, so USB
    // comes up concurrently with SD init and capture rather than after them.
    let driver: UsbDriver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));
    let mut cfg = UsbConfig::new(0xc0de, 0xca9d);
    cfg.manufacturer = Some("Sonde");
    cfg.product = Some("Capture SD");
    cfg.serial_number = Some("headless");
    cfg.max_power = 100;
    cfg.max_packet_size_0 = 64;

    static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static MSOS_DESC: StaticCell<[u8; 64]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 128]> = StaticCell::new();
    let mut builder = Builder::new(
        driver,
        cfg,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 256]),
        MSOS_DESC.init([0; 64]),
        CONTROL_BUF.init([0; 128]),
    );
    // Mass Storage class: SCSI transparent command set (0x06), Bulk-Only (0x50).
    let mut func = builder.function(0x08, 0x06, 0x50);
    let mut iface = func.interface();
    let mut alt = iface.alt_setting(0x08, 0x06, 0x50, None);
    let mut ep_in = alt.endpoint_bulk_in(None, 64);
    let mut ep_out = alt.endpoint_bulk_out(None, 64);
    drop(func);
    let mut device: UsbDevice<'static, UsbDriver> = builder.build();

    // microSD on SPIM2: SCK P1.13, MISO P1.14, MOSI P1.15, CS P1.12 (free pins).
    // Construction is sync; the init handshake runs inside the async block below.
    let mut sconf = spim::Config::default();
    sconf.frequency = spim::Frequency::M4;
    let spi = Spim::new(p.SPI2, Irqs, p.P1_13, p.P1_14, p.P1_15, sconf);
    let cs = Output::new(p.P1_12, Level::High, OutputDrive::Standard);
    let mut sd = SdCard::new(spi, cs);

    // Card bring-up + writer + MSC service. This is the only part that depends on
    // the SD card, so it is the only part gated on `sd.init()`; USB enumeration and
    // capture (above) run concurrently with it via the join.
    let storage = async {
        if sd.init().await.is_err() {
            led::fatal_blink(); // no card → nothing to serve or write
        }
        persist_panic(&mut sd).await;
        // Load the run index, finalize any run a prior crash left open, open this
        // boot's run, and persist the superblock so finalized runs are visible now.
        let mut ix = {
            let mut b = [0u8; 512];
            match sd.read_block(SUPERBLOCK_LBA, &mut b).await {
                Ok(()) => RunIndex::decode(&b),
                Err(_) => RunIndex::empty(),
            }
        };
        ix.close_unfinalized();
        // Only capture modes open a run. Non-capture boots (RSSI/Zigbee — the radio
        // has no SD path) just serve existing files over USB, so opening a run here
        // would leave a zero-length entry every such boot.
        let mut run = 0usize;
        let mut start_lba = 0u32;
        if capture {
            let (rmode, rkind) = match mode {
                BootMode::GattEnum => (Mode::Gatt, Kind::Text),
                BootMode::ConnFollow => (Mode::ConnFollow, Kind::Pcap),
                _ => (Mode::Sniff, Kind::Pcap),
            };
            run = ix.start(rmode, rkind).unwrap_or(0);
            start_lba = ix.runs.get(run).map(|r| r.start_lba).unwrap_or(0);
        }
        // Persist the index (prior runs now finalized, plus this boot's new run if
        // any) so finalized runs are visible to the host immediately.
        {
            let sb = ix.encode();
            let _ = sd.write_block(SUPERBLOCK_LBA, &sb).await;
        }
        let card: &'static SharedCard = CARD.init(Mutex::new(sd));
        let index: &'static SharedIndex = INDEX.init(Mutex::new(ix));
        if capture {
            spawner.spawn(sd_writer(card, index, run, start_lba).unwrap());
        }
        usb_msc::serve(&mut ep_in, &mut ep_out, card, index).await
    };

    join(device.run(), storage).await;
    led::fatal_blink();
}
