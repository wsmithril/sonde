#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_nrf::qspi::{self, Qspi};
use embassy_nrf::spim::{self, Spim};
use embassy_nrf::usb::{self, Driver, vbus_detect::HardwareVbusDetect};
use embassy_nrf::{Peri, bind_interrupts, peripherals};
use embassy_usb::class::cdc_acm::{CdcAcmClass, Receiver, Sender, State};
use embassy_usb::{Builder, Config as UsbConfig, UsbDevice};
use static_cell::StaticCell;
// The panic handler lives in `panic`, which records the crash site to flash and
// halts on a blinking LED. `panic_probe` is deliberately not used: it reports
// through RTT, which nothing reads without a debugger, and then hard-faults into
// a silent loop that looks exactly like a wedged radio.
use defmt_rtt as _;

// Shared library surface: the mode logic, decoders, and the log pipeline all live
// in `sonde_common`; this binary supplies the USB CDC console and the dispatch.
use sonde_common::boot::{self, BootMode, next_boot_mode};
use sonde_common::{
    LOG, LOG_DROPPED, Rng, ble_sniff, common, conn_follow, decoder, gatt, panic,
    rssi, ulog, ulogf, wallclock, zb_sniff,
};

/// Onboard RGB LED backend + indicator tasks (XIAO-specific hardware).
mod led;
use led::Sink as _; // `.set()` on the LED backends is a trait method.

// ── Interrupt binding ─────────────────────────────────────────────────────────

bind_interrupts!(struct Irqs {
    SPIM3       => spim::InterruptHandler<peripherals::SPI3>;
    QSPI        => qspi::InterruptHandler<peripherals::QSPI>;
    USBD        => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => usb::vbus_detect::InterruptHandler;
});


// ── Tasks ─────────────────────────────────────────────────────────────────────

/// BLE-sniff mode: a BLE advertising scan across the primary channels with inline
/// AuxPtr following ([`ble_sniff::scan`]), forever. Each captured packet is queued
/// for [`ble_sniff::log_task`] to decode. The onboard RGB LED shows capture rate
/// and loss via [`sniff_led`], which samples counters rather than being driven
/// from this path.
#[embassy_executor::task]
async fn ble_task() {
    ulog!("mode=ble_sniff\r\n");
    ble_sniff::use_fast_ramp_up();
    let mut rng = Rng(0x1234_5678); // seed; stirred with RSSI noise each cycle
    loop {
        ble_sniff::scan(&mut rng).await;
    }
}

/// Zigbee-sniff mode: an IEEE 802.15.4 survey of channels 11–26 — an energy sweep
/// to find the occupied channels, then a dwell on each biased toward what the
/// sweep found ([`zb_sniff::scan`]), forever. Captured frames are queued for
/// [`zb_sniff::log_task`] to decode down to the MAC header; payloads are AES-CCM*
/// encrypted, so presence and topology are the deliverable, not content.
///
/// The task owns the LED as a `led::Gpio` and drives it per event, like
/// conn-follow and unlike the two modes with an indicator task: frames arrive
/// sparsely enough that a rate-sampling indicator would read as permanently dark.
/// Green while the energy sweep runs, a red flash on each channel change, a blue
/// flash per captured frame.
#[embassy_executor::task]
async fn zb_task(mut leds: led::Gpio) {
    ulog!("mode=zb_sniff\r\n");
    // Fast ramp-up is safe here for the same reason it is in the BLE sniffer:
    // this is RX-only, with no T_IFS turnaround for the shorter ramp to miss.
    ble_sniff::use_fast_ramp_up();
    let mut rng = Rng(0x5EED_15A4);
    loop {
        zb_sniff::scan(&mut rng, &mut leds).await;
    }
}

/// RSSI-monitor mode: an RSSI spectrum sweep to the WS2812 strip plus the onboard
/// RGB LED (via PWM) coloured from the average signal strength ([`rssi::sweep`]),
/// forever. `rng` is stirred with noise-floor entropy each sweep.
#[embassy_executor::task]
async fn rssi_task(mut spi: Spim<'static>, mut leds: led::Pwm) {
    ulog!("mode=rssi_monitor\r\n");
    let mut rng = Rng(0x1234_5678);
    loop {
        rssi::sweep(&mut spi, &mut rng, &mut leds).await;
    }
}

/// GATT-enum mode: an active BLE central that surveys connectable advertisers,
/// connects to the strongest one not seen in the last hour, walks its GATT table
/// (services/characteristics/descriptors + value reads), then disconnects and
/// repeats ([`gatt::run`]). The onboard RGB LED reflects state (scanning →
/// connected → reading → error) via [`LED_SET`]/[`led_indicator`].
#[embassy_executor::task]
async fn gatt_task() {
    ulog!("mode=gatt_enum\r\n");
    let mut rng = Rng(0x1234_5678); // seed; stirred with RSSI noise each cycle
    loop {
        gatt::run(&mut rng).await;
    }
}

/// Conn-follow mode: a passive follower that listens for a `CONNECT_IND`, follows
/// the connection onto the data channels until it ends, and repeats. Drives the
/// onboard RGB LEDs directly (no `led_indicator` task): blue blinks per
/// advertising packet while listening, then during a follow blue for a captured
/// event, red for a missed one and a green flash per event carrying a payload
/// ([`conn_follow::run`]).
#[embassy_executor::task]
async fn conn_follow_task(leds: led::Gpio) {
    ulog!("mode=conn_follow\r\n");
    conn_follow::run(leds).await;
}

// ── USB CDC serial ──────────────────────────────────────────────────────────
//
// The CDC-ACM class exposes a serial port (appears as /dev/tty.usbmodem*)
// carrying two independent flows:
//   • TX (`drain_log`): streams the LOG channel to the host as timestamped lines.
//   • RX (`provision`): in BLE-sniff mode, receives the external-flash asset
//     image (see `provision` below and the host `builder` crate).
// `usb_logger` runs TX only (RSSI / GATT modes); `usb_task` runs TX + RX and
// owns the QSPI driver so the XIP window stays mapped for lookups.

type UsbDriver = Driver<'static, HardwareVbusDetect>;

// StaticCell gives a &'static mut T on first call to init(), panicking on
// reuse — safe here because exactly one USB task is spawned per boot.
static USB_STATE:     StaticCell<State<'static>> = StaticCell::new();
static USB_CFG_DESC:  StaticCell<[u8; 256]>      = StaticCell::new();
static USB_BOS_DESC:  StaticCell<[u8; 64]>       = StaticCell::new();
static USB_MSOS_DESC: StaticCell<[u8; 0]>        = StaticCell::new();
static USB_CTRL_BUF:  StaticCell<[u8; 64]>       = StaticCell::new();

/// Build the USB device + CDC-ACM class. The shared StaticCells are initialised
/// here, so this runs once per boot (from the single spawned USB task).
fn build_usb(driver: UsbDriver) -> (UsbDevice<'static, UsbDriver>, CdcAcmClass<'static, UsbDriver>) {
    let mut config = UsbConfig::new(0xc0de, 0xcafe);
    config.manufacturer      = Some("Sonde");
    config.product           = Some("Sonde BLE Probe");
    config.max_packet_size_0 = 64;

    let state = USB_STATE.init(State::new());
    let mut builder = Builder::new(
        driver, config,
        USB_CFG_DESC.init([0; 256]),
        USB_BOS_DESC.init([0; 64]),
        USB_MSOS_DESC.init([]),
        USB_CTRL_BUF.init([0; 64]),
    );
    let class = CdcAcmClass::new(&mut builder, state, 64);
    let usb = builder.build();
    (usb, class)
}

/// One CDC bulk packet. The endpoint is declared with this size in
/// [`build_usb`]; a write of fewer bytes is a short packet, which ends the
/// transfer.
const CDC_PKT: usize = 64;

/// Append `src` to `pkt`, shipping a full packet whenever one is complete.
async fn cdc_push(
    tx: &mut Sender<'static, UsbDriver>,
    pkt: &mut [u8; CDC_PKT],
    n: &mut usize,
    mut src: &[u8],
) -> Result<(), ()> {
    while !src.is_empty() {
        let take = (CDC_PKT - *n).min(src.len());
        pkt[*n..*n + take].copy_from_slice(&src[..take]);
        *n += take;
        src = &src[take..];
        if *n == CDC_PKT {
            tx.write_packet(pkt).await.map_err(|_| ())?;
            *n = 0;
        }
    }
    Ok(())
}

/// Ship whatever is staged, as a short packet.
async fn cdc_flush(
    tx: &mut Sender<'static, UsbDriver>,
    pkt: &[u8; CDC_PKT],
    n: &mut usize,
) -> Result<(), ()> {
    if *n > 0 {
        tx.write_packet(&pkt[..*n]).await.map_err(|_| ())?;
        *n = 0;
    }
    Ok(())
}

/// Stream the LOG channel to the host: each line is preceded by a
/// "[SSSSSS.mmm] " timestamp — the instant the line was *queued*, taken from the
/// channel item, not read here. Waits for a host connection first; the channel
/// buffers lines posted before a terminal is open. On an endpoint error the
/// connection loop re-arms.
///
/// Lines are packed back to back into full 64-byte packets rather than each
/// getting packets of its own. A line averages 65 bytes, so a packet per
/// timestamp plus a packet per body made two short bulk transfers per line —
/// ~4600 a second under sniff load, which the endpoint could not sustain: every
/// capture lost about a tenth of its lines to [`LOG`] overflowing behind it.
/// Packing halves the transfer count, makes all but the last full-size, and
/// removes the per-line round trip.
///
/// The staged remainder is flushed whenever the channel runs dry, so a quiet
/// link still delivers its last line immediately instead of holding it until
/// some later line happens to fill the packet.
async fn drain_log(tx: &mut Sender<'static, UsbDriver>) {
    let mut pkt = [0u8; CDC_PKT];
    loop {
        tx.wait_connection().await;
        // Staging restarts empty on every reconnect: a partial packet left over
        // from the dropped connection belongs to a stream the host is no longer
        // reading, and shipping it would splice half a line onto the new one.
        let mut n = 0usize;
        'connected: loop {
            let item = match LOG.try_receive() {
                Ok(v) => v,
                Err(_) => {
                    if cdc_flush(tx, &pkt, &mut n).await.is_err() {
                        break 'connected;
                    }
                    LOG.receive().await
                }
            };
            let (queued_at, msg) = item;

            let lost = LOG_DROPPED.swap(0, core::sync::atomic::Ordering::Relaxed);
            if lost != 0 {
                use core::fmt::Write;
                let mut s: heapless::String<48> = heapless::String::new();
                let _ = write!(s, "*** {} log lines dropped (queue full)\r\n", lost);
                if cdc_push(tx, &mut pkt, &mut n, s.as_bytes()).await.is_err() {
                    break 'connected;
                }
            }

            {
                // Uptime `[SSSSSS.mmm]` until a peer's Current Time is read in GATT
                // mode, then ISO-8601 UTC — see `wallclock`.
                let mut prefix: heapless::String<32> = heapless::String::new();
                wallclock::write_prefix(&mut prefix, queued_at);
                if cdc_push(tx, &mut pkt, &mut n, prefix.as_bytes()).await.is_err() {
                    break 'connected;
                }
            }

            if cdc_push(tx, &mut pkt, &mut n, msg.as_bytes()).await.is_err() {
                break 'connected;
            }
        }
    }
}

/// TX-only USB task for modes that do not access external flash (RSSI, GATT).
#[embassy_executor::task]
async fn usb_logger(driver: UsbDriver) {
    let (mut usb, class) = build_usb(driver);
    let (mut tx, _rx) = class.split();
    embassy_futures::join::join(usb.run(), drain_log(&mut tx)).await;
}

/// USB run + TX-log task for BLE-sniff mode. Spawned before QSPI bring-up so a
/// tty and the serial log are available even if the QSPI init stalls or faults.
/// The `Sender` half streams the log; the `Receiver` half goes to `provision_task`.
#[embassy_executor::task]
async fn usb_run(
    mut usb: UsbDevice<'static, UsbDriver>,
    mut tx: Sender<'static, UsbDriver>,
) {
    embassy_futures::join::join(usb.run(), drain_log(&mut tx)).await;
}

/// BLE-sniff provisioning task: owns the QSPI driver (keeping the XIP window
/// mapped for OUI / company / UUID lookups) and services the CDC protocol.
#[embassy_executor::task]
async fn provision_task(mut rx: Receiver<'static, UsbDriver>, qspi: Qspi<'static>) {
    provision(&mut rx, qspi).await;
}

/// Owns the QSPI driver for modes that read the asset tables but never provision
/// them, keeping the memory-mapped (XIP) window valid for the whole session.
#[embassy_executor::task]
async fn qspi_hold(_qspi: Qspi<'static>) -> ! {
    loop {
        embassy_time::Timer::after_secs(3600).await;
    }
}

/// Bring up the on-board P25Q16H (2 MB) over QSPI, memory-mapped (XIP) at
/// 0x1200_0000, holding the OUI / company / UUID lookup tables. Single-IO opcodes
/// (Fastread 0x0B / page-program 0x02) avoid QE-bit management; deep-power-down
/// is left off. Pins: SCK=P0.21, CSN=P0.25, IO0=P0.20, IO1=P0.24, IO2=P0.22,
/// IO3=P0.23.
fn qspi_setup(
    qspi: Peri<'static, peripherals::QSPI>,
    sck: Peri<'static, peripherals::P0_21>,
    csn: Peri<'static, peripherals::P0_25>,
    io0: Peri<'static, peripherals::P0_20>,
    io1: Peri<'static, peripherals::P0_24>,
    io2: Peri<'static, peripherals::P0_22>,
    io3: Peri<'static, peripherals::P0_23>,
) -> Qspi<'static> {
    let mut cfg = qspi::Config::default();
    cfg.read_opcode = qspi::ReadOpcode::Fastread;
    cfg.write_opcode = qspi::WriteOpcode::Pp;
    cfg.frequency = qspi::Frequency::M32;
    cfg.deep_power_down = None;
    cfg.capacity = 0x20_0000;
    Qspi::new(qspi, Irqs, sck, csn, io0, io1, io2, io3, cfg)
}

/// Mark the provisioned tables available and hold the QSPI driver for the session,
/// so UUID / company-ID lookups resolve to names. For modes that read the tables
/// but never provision them (GATT enum, conn-follow); `qspi_hold` owns the driver
/// because dropping it unmaps the memory-mapped (XIP) window the lookups read.
fn hold_assets(spawner: Spawner, qspi: Qspi<'static>) {
    decoder::asset::header_check();
    ulogf!("qspi: ready={}", decoder::asset::is_ready());
    spawner.spawn(qspi_hold(qspi).unwrap());
}

// ── External-flash provisioning (device side) ─────────────────────────────────
//
// Receives the asset image over CDC and writes it to the QSPI flash. Protocol
// (matches the host `builder provision` subcommand):
//   host → device:  "BSPROV\n" | len:u32 LE | crc:u32 LE
//   device → host:  "PROV_ERASED"                (region erased, ready for data)
//   host → device:  <len> payload bytes
//   device → host:  "PROV_OK" | "PROV_ERR"
// The header {magic,len,crc} at flash offset 0 is written LAST, so an aborted
// transfer never leaves a valid-looking image (see decoder::asset).

const HANDSHAKE: [u8; 7] = *b"BSPROV\n";
const SECTOR: u32 = 4096;

/// Word-aligned scratch buffer: QSPI `blocking_write` requires a 4-byte-aligned
/// source pointer and a length that is a multiple of 4.
#[repr(align(4))]
struct Aligned([u8; 64]);

async fn provision(rx: &mut Receiver<'static, UsbDriver>, mut qspi: Qspi<'static>) {
    use decoder::asset;
    let mut buf = Aligned([0u8; 64]);
    ulog!("prov: waiting for handshake\r\n");
    loop {
        let Some((len, want_crc)) = read_handshake(rx, &mut buf.0).await else {
            ulog!("prov: bad handshake, retrying\r\n");
            continue;
        };
        ulogf!(
            "prov: handshake len={} crc=0x{:08x} (build crc=0x{:08x})",
            len, want_crc, asset::ASSET_CRC32
        );

        // Reject early if the image doesn't match this firmware build — no point
        // erasing for a payload we'll refuse to commit.
        if len != asset::ASSET_LEN {
            ulogf!("prov: len mismatch, expected {}", asset::ASSET_LEN);
            ulog!("PROV_ERR\r\n");
            continue;
        }

        // Gate lookups off, then erase enough 4 KB sectors for header + payload.
        asset::set_provisioning(true);
        let sectors = (asset::HDR_SIZE + len).div_ceil(SECTOR);
        ulogf!("prov: erasing {} sectors ({} KB)", sectors, sectors * 4);
        let mut ok = true;
        for i in 0..sectors {
            if qspi.blocking_erase(i * SECTOR).is_err() {
                ulogf!("prov: erase failed at sector {}", i);
                ok = false;
                break;
            }
        }
        if !ok {
            asset::set_provisioning(false);
            ulog!("PROV_ERR\r\n");
            continue;
        }
        ulog!("PROV_ERASED\r\n");

        // Stream the payload to flash at offset HDR_SIZE, checksumming as we go.
        let mut off = 0u32;
        let mut crc = 0xFFFF_FFFFu32;
        let mut next_report = SECTOR * 16; // progress every 64 KB
        while off < len {
            let n = match rx.read_packet(&mut buf.0).await {
                Ok(n) => n,
                Err(_) => {
                    ulogf!("prov: read error at offset {}", off);
                    ok = false;
                    break;
                }
            };
            if n == 0 {
                continue;
            }
            let take = core::cmp::min(n as u32, len - off) as usize;
            crc = crc32_update(crc, &buf.0[..take]);
            // Pad the tail to a word boundary; erased flash already reads 0xFF.
            let wlen = (take + 3) & !3;
            for b in &mut buf.0[take..wlen] {
                *b = 0xFF;
            }
            if qspi.blocking_write(asset::HDR_SIZE + off, &buf.0[..wlen]).is_err() {
                ulogf!("prov: write failed at offset {}", off);
                ok = false;
                break;
            }
            off += take as u32;
            if off >= next_report {
                ulogf!("prov: {}/{} bytes", off, len);
                next_report += SECTOR * 16;
            }
        }
        if ok {
            ulogf!("prov: received {}/{} bytes", off, len);
        }

        // Verify the transfer (stream crc == host's crc) and that the image
        // matches this firmware build (== the crc baked in at compile time),
        // then commit by writing the header last.
        let got = !crc;
        if ok && got == want_crc && got == asset::ASSET_CRC32 {
            ulog!("prov: crc ok, writing header\r\n");
            let mut hdr = Aligned([0xFFu8; 64]);
            hdr.0[0..4].copy_from_slice(&asset::ASSET_MAGIC.to_le_bytes());
            hdr.0[4..8].copy_from_slice(&len.to_le_bytes());
            hdr.0[8..12].copy_from_slice(&want_crc.to_le_bytes());
            ok = qspi.blocking_write(0, &hdr.0[..12]).is_ok();
            if !ok {
                ulog!("prov: header write failed\r\n");
            }
        } else {
            ulogf!(
                "prov: crc/verify mismatch got=0x{:08x} want=0x{:08x} build=0x{:08x} ok={}",
                got, want_crc, asset::ASSET_CRC32, ok
            );
            ok = false;
        }

        asset::set_provisioning(false);
        if ok {
            asset::header_check();
            ulog!("PROV_OK\r\n");
        } else {
            ulog!("PROV_ERR\r\n");
        }
    }
}

/// Read the 15-byte handshake (`"BSPROV\n"` + len + crc) across CDC packets,
/// returning `(len, crc)` on a valid header or `None` to retry.
async fn read_handshake(rx: &mut Receiver<'static, UsbDriver>, buf: &mut [u8]) -> Option<(u32, u32)> {
    let mut acc = [0u8; 15];
    let mut have = 0usize;
    while have < acc.len() {
        let n = rx.read_packet(buf).await.ok()?;
        for &b in &buf[..n] {
            if have < acc.len() {
                acc[have] = b;
                have += 1;
            }
        }
    }
    if acc[..7] != HANDSHAKE {
        return None;
    }
    let len = u32::from_le_bytes([acc[7], acc[8], acc[9], acc[10]]);
    let crc = u32::from_le_bytes([acc[11], acc[12], acc[13], acc[14]]);
    Some((len, crc))
}

/// CRC-32/ISO-HDLC streaming update (finalise with `!crc`). Matches build.rs and
/// the host `builder` crate so the device's checksum matches the image's.
fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Hold the onboard RGB LED for ~1 s in this boot's mode colour. GPIO rather than
/// PWM because this runs before the executor and before the mode arm claims the
/// pins; the pins are stolen and released so the arm can claim them properly.
fn indicate(mode: BootMode) {
    let mut leds = unsafe { led::Gpio::steal() };
    leds.set(match mode {
        BootMode::BleSniff => led::BLUE,
        BootMode::RssiMonitor => led::GREEN,
        BootMode::GattEnum => led::RED,
        BootMode::ConnFollow => led::WHITE,
        BootMode::ZigbeeSniff => led::CYAN,
    });
    cortex_m::asm::delay(64_000_000); // ~1 s at the 64 MHz core clock
    leds.set(led::OFF);
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // ── Boot blink sequence ───────────────────────────────────────────────────
    // Each LED lights briefly in sequence to show which init step completed.
    // Wherever the sequence stops = where the hang is.
    // Remove this block once the board is confirmed stable.
    //
    // Expected sequence on a healthy boot:
    //   RED on   → embassy_nrf::init() done
    //   RED off, BLUE on  → radio_configure_ble() done
    //   BLUE off, GREEN on → SPI init done
    //   GREEN off → tasks spawned, normal operation begins

    // Clock setup (HFXO for the radio, synthesized LFCLK for embassy-time) is
    // shared with the headless build — see `boot::clock_config` for the rationale.
    let p = embassy_nrf::init(boot::clock_config());

    // Checkpoint 1: embassy init done — red blink + serial log. The pins are
    // stolen for each checkpoint and released again, because the mode arm below
    // claims them properly once it knows which backend it wants.
    let mut dbg = unsafe { led::Gpio::steal() };
    dbg.set(led::RED);
    cortex_m::asm::delay(3_000_000);
    dbg.set(led::OFF);
    drop(dbg);
    ulog!("init_ok\r\n");

    common::radio_configure_ble();

    // Checkpoint 2: radio configured — blue blink + serial log
    let mut dbg = unsafe { led::Gpio::steal() };
    dbg.set(led::BLUE);
    cortex_m::asm::delay(3_000_000);
    dbg.set(led::OFF);
    drop(dbg);
    ulog!("radio_ok\r\n");

    // USB CDC serial logger — appears as /dev/tty.usbmodem* when firmware runs.
    // Open with: screen /dev/tty.usbmodem* 115200
    let usb_driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

    // Select this boot's mode (advances on every reset; persisted in flash).
    let mode = next_boot_mode(p.NVMC);

    // Anything the last run died of, before this run's output starts. Queued
    // like any other line, so it waits in LOG until a terminal opens. Runs after
    // `next_boot_mode` because that borrows NVMC and this reclaims it raw.
    panic::report_and_clear();

    // Boot-mode indicator: hold the onboard RGB LED for ~1 s in this boot's mode
    // colour so the active mode is visible immediately after reset.
    indicate(mode);

    match mode {
        BootMode::BleSniff => {
            // Bring USB up FIRST, in its own task, so a tty and the serial log are
            // available even if the QSPI bring-up below stalls or faults. Yield
            // long enough for the host to enumerate before we touch the QSPI.
            let (usb, class) = build_usb(usb_driver);
            let (tx, rx) = class.split();
            spawner.spawn(usb_run(usb, tx).unwrap());
            embassy_time::Timer::after_millis(1500).await;

            ulog!("qspi: init start\r\n");
            embassy_time::Timer::after_millis(50).await; // let the log flush

            // Sticky LED checkpoints: if the firmware freezes or faults during QSPI
            // bring-up, the last-lit colour stays on so the failing step is visible
            // with no serial monitor — RED = inside `qspi_setup`, GREEN = inside
            // `header_check`. Each is cleared on success, and the pins are released
            // for the indicator below.
            let mut ck = unsafe { led::Gpio::steal() };
            ck.set(led::RED);
            let qspi = qspi_setup(
                p.QSPI, p.P0_21, p.P0_25, p.P0_20, p.P0_24, p.P0_22, p.P0_23,
            );
            ck.set(led::GREEN); // RED off — qspi_setup returned
            ulog!("qspi: init ok\r\n");
            embassy_time::Timer::after_millis(50).await;

            // Mark the tables available if a valid image is already provisioned.
            decoder::asset::header_check();
            ck.set(led::OFF); // GREEN off — header_check returned
            drop(ck);
            ulogf!("qspi: ready={}", decoder::asset::is_ready());

            let pwm = led::Pwm::new(p.PWM0, p.P0_26, p.P0_30, p.P0_06);
            spawner.spawn(led::sniff(pwm).unwrap());
            spawner.spawn(ble_task().unwrap());
            // Decode/format lives in its own task, so it overlaps the reception
            // ble_task is doing.
            spawner.spawn(ble_sniff::log_task().unwrap());
            // Provisioning owns the QSPI, keeping XIP mapped for the whole session.
            spawner.spawn(provision_task(rx, qspi).unwrap());
        }
        BootMode::RssiMonitor => {
            // WS2812 strip over SPI (P1.11). Checkpoint 3 doubles as the SPI blink.
            let mut spi_config = spim::Config::default();
            spi_config.frequency = spim::Frequency::M2;
            let spi = Spim::new_txonly_nosck(p.SPI3, Irqs, p.P1_11, spi_config);

            let mut dbg = unsafe { led::Gpio::steal() };
            dbg.set(led::GREEN);
            cortex_m::asm::delay(3_000_000);
            dbg.set(led::OFF);
            drop(dbg);
            ulog!("spi_ok\r\n");

            let pwm = led::Pwm::new(p.PWM0, p.P0_26, p.P0_30, p.P0_06);
            spawner.spawn(rssi_task(spi, pwm).unwrap());
            spawner.spawn(usb_logger(usb_driver).unwrap());
        }
        BootMode::GattEnum => {
            // Reuse the onboard RGB LED as a connection-state indicator, driven
            // through `led::LED`:
            //   Blue   — surveying / scanning for a target
            //   Green  — connected, walking the GATT table
            //   Yellow — a failed attempt
            //   Red    — an ATT error / failed connection
            //   Off    — idle between targets

            // Map the QSPI asset window so the service/characteristic UUIDs the
            // enumeration walks resolve to names from the provisioned tables.
            let qspi = qspi_setup(
                p.QSPI, p.P0_21, p.P0_25, p.P0_20, p.P0_24, p.P0_22, p.P0_23,
            );
            hold_assets(spawner, qspi);

            let pwm = led::Pwm::new(p.PWM0, p.P0_26, p.P0_30, p.P0_06);
            spawner.spawn(led::indicator(pwm).unwrap());
            spawner.spawn(gatt_task().unwrap());
            spawner.spawn(usb_logger(usb_driver).unwrap());
        }
        BootMode::ConnFollow => {
            // Map the QSPI asset window so LL_VERSION_IND company IDs and ATT UUIDs
            // resolve to names from the provisioned tables.
            let qspi = qspi_setup(
                p.QSPI, p.P0_21, p.P0_25, p.P0_20, p.P0_24, p.P0_22, p.P0_23,
            );
            hold_assets(spawner, qspi);

            // The follower owns the LED as a `led::Gpio` and toggles channels
            // between radio events, so there is no indicator task here — a PWM
            // update's ~64 µs busy-wait has no place inside a connection event:
            //   Blue  — 1 ms blink on each advertising PDU received
            //   Green — a central (master) packet captured while following
            //   Red   — a peripheral (slave) packet captured while following
            let leds = led::Gpio::new(p.P0_26, p.P0_30, p.P0_06);
            spawner.spawn(conn_follow_task(leds).unwrap());
            // Decode/format lives in its own task, so it runs between the
            // connection events the follower is timing itself against.
            spawner.spawn(conn_follow::log_task().unwrap());
            spawner.spawn(usb_logger(usb_driver).unwrap());
        }
        BootMode::ZigbeeSniff => {
            // Reconfigure the radio for 802.15.4, undoing the BLE setup every boot
            // does before the mode is known.
            common::radio_configure_154();

            // No QSPI: the provisioned tables are BT SIG company IDs and BLE
            // UUIDs, and nothing in an 802.15.4 MAC header resolves against them.
            let leds = led::Gpio::new(p.P0_26, p.P0_30, p.P0_06);
            spawner.spawn(zb_task(leds).unwrap());
            spawner.spawn(zb_sniff::log_task().unwrap());
            spawner.spawn(usb_logger(usb_driver).unwrap());
        }
    }
}
