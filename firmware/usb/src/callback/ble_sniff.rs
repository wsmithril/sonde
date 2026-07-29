//! BLE-sniff mode (usb): the radio producer + console-decode consumer, plus the
//! external-flash asset provisioning path. BLE-sniff owns the QSPI and services CDC
//! provisioning, keeping the memory-mapped (XIP) window mapped for OUI / company /
//! UUID lookups the decoders make. The provisioning protocol lives here because it
//! is specific to this mode (no other mode receives an image over CDC).

use embassy_executor::Spawner;
use embassy_nrf::qspi::Qspi;
use embassy_usb::class::cdc_acm::Receiver;

use sonde_common::decoder;
use sonde_common::led::OnBoardLed as _;
use sonde_common::mode::{self, Mode as _};
use sonde_common::{led, ulog, ulogf};

use crate::{CTX, ConsoleSink, LedParts, QspiParts, UsbDriver};

/// BLE-sniff provisioning task: owns the QSPI driver (keeping the XIP window mapped
/// for lookups) and services the CDC provisioning protocol.
#[embassy_executor::task]
async fn provision_task(mut rx: Receiver<'static, UsbDriver>, qspi: Qspi<'static>) {
    provision(&mut rx, qspi).await;
}

#[embassy_executor::task]
pub async fn run(spawner: Spawner, rx: Receiver<'static, UsbDriver>, q: QspiParts, l: LedParts) {
    ulog!("mode=ble_sniff\r\n");
    let mut m = mode::BleSniff::<ConsoleSink>::new();
    // The build-specific callback the mode `await`s in `init`: bring up the QSPI
    // asset window, hand it to provisioning, and start the rate/liveness LED.
    m.init(&CTX, async move {
        // USB is already up; yield long enough for the host to enumerate before we
        // touch the QSPI (whose bring-up can stall or fault).
        embassy_time::Timer::after_millis(1500).await;
        ulog!("qspi: init start\r\n");
        embassy_time::Timer::after_millis(50).await; // let the log flush

        // Sticky LED checkpoints: if the firmware freezes during QSPI bring-up, the
        // last-lit colour stays on so the failing step is visible with no serial
        // monitor — RED = inside `qspi_setup`, GREEN = inside `header_check`.
        let mut ck = unsafe { led::Gpio::steal() };
        ck.set(led::RED);
        let qspi = crate::qspi_setup(q);
        ck.set(led::GREEN); // RED off — qspi_setup returned
        ulog!("qspi: init ok\r\n");
        embassy_time::Timer::after_millis(50).await;

        decoder::asset::header_check();
        ck.set(led::OFF); // GREEN off — header_check returned
        drop(ck);
        ulogf!("qspi: ready={}", decoder::asset::is_ready());

        // Provisioning owns the QSPI, keeping XIP mapped for the whole session.
        spawner.spawn(provision_task(rx, qspi).unwrap());

        // The rate/liveness LED indicator.
        let pwm = led::Pwm::new(l.pwm, l.r, l.g, l.b);
        spawner.spawn(mode::ble_sniff::led_task(pwm).unwrap());
    })
    .await;
    m.run(&CTX).await
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

        // Reject early if the image doesn't match this firmware build.
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

        // Verify (stream crc == host crc == build crc) then commit by writing the
        // header last.
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
