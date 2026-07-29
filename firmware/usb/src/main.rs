#![no_std]
#![no_main]

//! `sonde-usb`: the USB-console build. `main` does the common hardware bring-up and
//! the shared platform — the CDC console/log pipeline, the QSPI asset-window
//! helpers, the capture sink + static context — then routes the selected boot mode
//! to its setup in [`callback`]. Each mode owns its peripheral wiring and tasks there;
//! nothing mode-specific lives in `main`.

use embassy_executor::Spawner;
use embassy_nrf::qspi::{self, Qspi};
use embassy_nrf::spim::{self, Spim};
use embassy_nrf::usb::{self, Driver, vbus_detect::HardwareVbusDetect};
use embassy_nrf::{Peri, bind_interrupts, peripherals};
use embassy_usb::class::cdc_acm::{CdcAcmClass, Sender, State};
use embassy_usb::{Builder, Config as UsbConfig, UsbDevice};
use static_cell::StaticCell;
// The panic handler lives in `sonde_common::panic`, which records the crash site to
// flash and halts on a blinking LED. `panic_probe` is deliberately not used: it
// reports through RTT, which nothing reads without a debugger, and then hard-faults
// into a silent loop that looks exactly like a wedged radio.
use defmt_rtt as _;

use sonde_common::boot::{self, BootMode, next_boot_mode};
use sonde_common::led::OnBoardLed as _;
use sonde_common::{LOG, LOG_DROPPED, Rng, decoder, hal, led, mode, panic, ulog, ulogf, wallclock};

mod callback;

// ── Interrupt binding ─────────────────────────────────────────────────────────

bind_interrupts!(struct Irqs {
    SPIM3       => spim::InterruptHandler<peripherals::SPI3>;
    QSPI        => qspi::InterruptHandler<peripherals::QSPI>;
    USBD        => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => usb::vbus_detect::InterruptHandler;
});

// ── Capture sink + context ──────────────────────────────────────────────────

/// USB build's capture sink (the "decode → phy" half): text goes straight to the
/// console log; a captured frame is decoded to console lines, stamped with its air
/// time.
pub(crate) struct ConsoleSink;
impl mode::CaptureSink for ConsoleSink {
    fn sink_text(&mut self, line: &str) {
        let mut l = sonde_common::LogLine::new();
        let _ = l.push_str(line);
        sonde_common::log_send(l);
    }
    fn sink_frame<F: mode::Frame>(&mut self, f: &F) {
        sonde_common::with_log_stamp(f.t_air(), || f.decode_to(&mut sonde_common::LogSink));
    }
}

/// This boot's static context (entropy + the console sink), so a mode's `run` can
/// be a spawned task rather than borrowing `main`'s locals.
pub(crate) static CTX: mode::Ctx<ConsoleSink> = mode::Ctx::new(Rng(0x1234_5678), ConsoleSink);

// ── Peripheral bundles ────────────────────────────────────────────────────────
//
// `run` has already consumed USBD + NVMC from `Peripherals`, so it can't pass the
// whole `p` on; instead it hands each mode only the peripherals that mode needs,
// grouped so the signatures stay short. The onboard RGB LED (P0.26/30/06) is on the
// same pins whether a mode drives it as PWM or GPIO.

/// QSPI peripheral + its six IO pins — the asset-window flash.
pub(crate) struct QspiParts {
    pub qspi: Peri<'static, peripherals::QSPI>,
    pub sck: Peri<'static, peripherals::P0_21>,
    pub csn: Peri<'static, peripherals::P0_25>,
    pub io0: Peri<'static, peripherals::P0_20>,
    pub io1: Peri<'static, peripherals::P0_24>,
    pub io2: Peri<'static, peripherals::P0_22>,
    pub io3: Peri<'static, peripherals::P0_23>,
}

/// The onboard RGB LED: PWM instance + the three channel pins.
pub(crate) struct LedParts {
    pub pwm: Peri<'static, peripherals::PWM0>,
    pub r: Peri<'static, peripherals::P0_26>,
    pub g: Peri<'static, peripherals::P0_30>,
    pub b: Peri<'static, peripherals::P0_06>,
}

// ── USB CDC serial ──────────────────────────────────────────────────────────
//
// The CDC-ACM class exposes a serial port (appears as /dev/tty.usbmodem*)
// carrying two independent flows:
//   • TX (`drain_log`): streams the LOG channel to the host as timestamped lines.
//   • RX (`provision`, in BLE-sniff mode): receives the external-flash asset image.

pub(crate) type UsbDriver = Driver<'static, HardwareVbusDetect>;

// StaticCell gives a &'static mut T on first call to init(), panicking on reuse —
// safe here because exactly one USB task is spawned per boot.
static USB_STATE: StaticCell<State<'static>> = StaticCell::new();
static USB_CFG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
static USB_BOS_DESC: StaticCell<[u8; 64]> = StaticCell::new();
static USB_MSOS_DESC: StaticCell<[u8; 0]> = StaticCell::new();
static USB_CTRL_BUF: StaticCell<[u8; 64]> = StaticCell::new();

/// Build the USB device + CDC-ACM class. The shared StaticCells are initialised
/// here, so this runs once per boot (from the single spawned USB task).
fn build_usb(driver: UsbDriver) -> (UsbDevice<'static, UsbDriver>, CdcAcmClass<'static, UsbDriver>) {
    let mut config = UsbConfig::new(0xc0de, 0xcafe);
    config.manufacturer = Some("Sonde");
    config.product = Some("Sonde BLE Probe");
    config.max_packet_size_0 = 64;

    let state = USB_STATE.init(State::new());
    let mut builder = Builder::new(
        driver,
        config,
        USB_CFG_DESC.init([0; 256]),
        USB_BOS_DESC.init([0; 64]),
        USB_MSOS_DESC.init([]),
        USB_CTRL_BUF.init([0; 64]),
    );
    let class = CdcAcmClass::new(&mut builder, state, 64);
    let usb = builder.build();
    (usb, class)
}

/// One CDC bulk packet. A write of fewer bytes is a short packet, ending the transfer.
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
async fn cdc_flush(tx: &mut Sender<'static, UsbDriver>, pkt: &[u8; CDC_PKT], n: &mut usize) -> Result<(), ()> {
    if *n > 0 {
        tx.write_packet(&pkt[..*n]).await.map_err(|_| ())?;
        *n = 0;
    }
    Ok(())
}

/// Log the read-only FICR chip identity as part of the boot sequence. The DTR-gated
/// `drain_log` guarantees it reaches a terminal that attaches later. A
/// remarked/clone/reject die reports the wrong values here — genuine nRF52840:
/// PART=0x52840, RAM=256, FLASH=1024, VARIANT ASCII like "AAD0".
fn log_chip() {
    use embassy_nrf::pac::FICR;
    let part = FICR.info().part().read().0;
    let ram = FICR.info().ram().read().0;
    let flash = FICR.info().flash().read().0;
    let vb = FICR.info().variant().read().to_be_bytes();
    let vc = |b: u8| if (0x20..0x7f).contains(&b) { b as char } else { '.' };
    ulogf!(
        "chip: PART=0x{:05X} VARIANT={}{}{}{} PACKAGE=0x{:X} RAM={}KB FLASH={}KB \
         DEVICEID={:08X}{:08X} genuine_nRF52840={}",
        part, vc(vb[0]), vc(vb[1]), vc(vb[2]), vc(vb[3]),
        FICR.info().package().read().0, ram, flash,
        FICR.deviceid(1).read(), FICR.deviceid(0).read(),
        part == 0x52840 && ram == 256 && flash == 1024
    );
}

/// Stream the LOG channel to the host, each line prefixed with its queued-at
/// timestamp. Gates on DTR so the boot backlog waits until a terminal opens the
/// port, then delivers it in order (with a few-second fallback for readers that
/// never assert DTR). Lines are packed into full 64-byte packets.
async fn drain_log(tx: &mut Sender<'static, UsbDriver>) {
    let mut pkt = [0u8; CDC_PKT];
    loop {
        tx.wait_connection().await;
        // `wait_connection` fires at endpoint-enable (enumeration), not when a
        // terminal opens the port — draining in that gap loses the boot backlog.
        // Gate on DTR so the backlog waits in LOG until someone is listening.
        let mut waited = 0u32;
        while !tx.dtr() && waited < 5000 {
            embassy_time::Timer::after_millis(50).await;
            waited += 50;
        }
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

/// USB run + TX-log task, spawned once per boot before the mode-indicator flash so
/// the tty and serial log come up during it.
#[embassy_executor::task]
async fn usb_run(mut usb: UsbDevice<'static, UsbDriver>, mut tx: Sender<'static, UsbDriver>) {
    embassy_futures::join::join(usb.run(), drain_log(&mut tx)).await;
}

// ── QSPI asset window ─────────────────────────────────────────────────────────

/// Owns the QSPI driver for modes that read the asset tables but never provision
/// them, keeping the memory-mapped (XIP) window valid for the whole session.
#[embassy_executor::task]
async fn qspi_hold(_qspi: Qspi<'static>) -> ! {
    loop {
        embassy_time::Timer::after_secs(3600).await;
    }
}

/// Bring up the on-board P25Q16H (2 MB) over QSPI, memory-mapped (XIP) at
/// 0x1200_0000, holding the OUI / company / UUID lookup tables. Pins: SCK=P0.21,
/// CSN=P0.25, IO0=P0.20, IO1=P0.24, IO2=P0.22, IO3=P0.23.
pub(crate) fn qspi_setup(q: QspiParts) -> Qspi<'static> {
    let mut cfg = qspi::Config::default();
    cfg.read_opcode = qspi::ReadOpcode::Fastread;
    cfg.write_opcode = qspi::WriteOpcode::Pp;
    cfg.frequency = qspi::Frequency::M32;
    cfg.deep_power_down = None;
    cfg.capacity = 0x20_0000;
    Qspi::new(q.qspi, Irqs, q.sck, q.csn, q.io0, q.io1, q.io2, q.io3, cfg)
}

/// Mark the provisioned tables available and hold the QSPI driver for the session,
/// so UUID / company-ID lookups resolve to names. For modes that read the tables
/// but never provision them (GATT enum, conn-follow, Midea); `qspi_hold` owns the
/// driver because dropping it unmaps the XIP window the lookups read.
pub(crate) fn hold_assets(spawner: Spawner, qspi: Qspi<'static>) {
    decoder::asset::header_check();
    ulogf!("qspi: ready={}", decoder::asset::is_ready());
    spawner.spawn(qspi_hold(qspi).unwrap());
}

/// The WS2812 strip SPI for the RSSI monitor: 2 MHz, TX-only, no SCK, on P1.11.
pub(crate) fn ws2812_spi(
    spi: Peri<'static, peripherals::SPI3>,
    din: Peri<'static, peripherals::P1_11>,
) -> Spim<'static> {
    let mut cfg = spim::Config::default();
    cfg.frequency = spim::Frequency::M2;
    Spim::new_txonly_nosck(spi, Irqs, din, cfg)
}

// ── Mode router ───────────────────────────────────────────────────────────────

/// Hold the onboard RGB LED for ~1 s in this boot's mode colour. GPIO rather than
/// PWM because this runs before the mode arm claims the pins; the pins are stolen
/// and released so the arm can claim them properly.
async fn indicate(mode: BootMode) {
    let mut leds = unsafe { led::Gpio::steal() };
    leds.set(match mode {
        BootMode::BleSniff => led::BLUE,
        BootMode::RssiMonitor => led::GREEN,
        BootMode::GattEnum => led::RED,
        BootMode::ConnFollow => led::WHITE,
        BootMode::ZigbeeSniff => led::CYAN,
        BootMode::MideaCtl => led::MAGENTA,
    });
    embassy_time::Timer::after_millis(1000).await;
    leds.set(led::OFF);
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Common hardware bring-up; everything mode-specific lives in `callback`.

    // Clock setup (HFXO for the radio, synthesized LFCLK for embassy-time) is shared
    // with the headless build — see `boot::clock_config` for the rationale.
    let p = embassy_nrf::init(boot::clock_config());

    // Boot checkpoints: each colour marks an init step, so wherever the sequence
    // stops is where a hang is. The pins are stolen and released again because the
    // mode arm claims them properly once it knows which backend it wants.
    // RED = embassy init done.
    let mut dbg = unsafe { led::Gpio::steal() };
    dbg.set(led::RED);
    cortex_m::asm::delay(3_000_000);
    dbg.set(led::OFF);
    drop(dbg);
    ulog!("init_ok\r\n");

    hal::radio::configure_ble();

    // BLUE = radio configured.
    let mut dbg = unsafe { led::Gpio::steal() };
    dbg.set(led::BLUE);
    cortex_m::asm::delay(3_000_000);
    dbg.set(led::OFF);
    drop(dbg);
    ulog!("radio_ok\r\n");

    // Chip identity, early in the boot sequence (drain_log holds the log until a
    // terminal opens the port, so it is delivered even to a late-attaching tty).
    log_chip();

    // USB CDC serial logger — appears as /dev/tty.usbmodem*. Open with:
    // screen /dev/tty.usbmodem* 115200
    let usb_driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

    // Select this boot's mode (advances on every reset; persisted in flash).
    let mode = next_boot_mode(p.NVMC);

    // Anything the last run died of, queued before this run's output. Runs after
    // `next_boot_mode` (which borrows NVMC) because it reclaims NVMC raw.
    panic::report_and_clear();

    // Bring USB up BEFORE the mode-colour flash so the tty enumerates and the log
    // starts draining during the ~1 s indicator. The `rx` half feeds BLE-sniff
    // provisioning and is dropped (unused) by every other mode.
    let (usb, class) = build_usb(usb_driver);
    let (tx, rx) = class.split();
    spawner.spawn(usb_run(usb, tx).unwrap());

    indicate(mode).await;

    // Spawn the selected mode's task. Each `callback::*` task builds the mode, then
    // hands it a build-specific `setup` future (QSPI/LED/provisioning) that the mode
    // `await`s inside `init`. Peripherals come from `p`'s remaining fields (USBD/NVMC
    // are already spent); only one arm runs, so moving the shared LED pins out of `p`
    // in several arms is fine.
    let qspi = || QspiParts {
        qspi: p.QSPI, sck: p.P0_21, csn: p.P0_25,
        io0: p.P0_20, io1: p.P0_24, io2: p.P0_22, io3: p.P0_23,
    };
    let leds = || LedParts { pwm: p.PWM0, r: p.P0_26, g: p.P0_30, b: p.P0_06 };
    match mode {
        BootMode::BleSniff => spawner.spawn(callback::ble_sniff::run(spawner, rx, qspi(), leds()).unwrap()),
        BootMode::RssiMonitor => spawner.spawn(callback::rssi::run(p.SPI3, p.P1_11, leds()).unwrap()),
        BootMode::GattEnum => spawner.spawn(callback::gatt::run(spawner, qspi(), leds()).unwrap()),
        BootMode::ConnFollow => spawner.spawn(callback::conn_follow::run(spawner, qspi(), leds()).unwrap()),
        BootMode::ZigbeeSniff => spawner.spawn(callback::zigbee::run(spawner, leds()).unwrap()),
        BootMode::MideaCtl => spawner.spawn(callback::midea::run(spawner, qspi(), leds()).unwrap()),
    }
}
