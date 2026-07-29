//! Read-only USB Mass Storage (Bulk-Only Transport + a minimal SCSI target),
//! serving the synthetic FAT32 view of the capture card.
//!
//! embassy-usb 0.6 ships no MSC class, so this drives raw bulk endpoints. Only
//! the commands a host needs to enumerate and read a removable read-only disk are
//! implemented; WRITE(10) is refused, so the host physically cannot alter the
//! card. Reads route through [`fat::Fat`]: metadata blocks are synthesized, file
//! data is read from the card (shared with the writer via a mutex). The `Fat` view
//! is rebuilt from the run index per command, so runs finalized since the last
//! command appear without a re-enumeration.
//!
//! HARDWARE-UNVERIFIED: the BOT/SCSI state machine and host enumeration need the
//! bench; only the FAT layout it serves has been validated on a host.

use embassy_nrf::usb::Driver;
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_usb::driver::{EndpointIn, EndpointOut};

use crate::storage::fat::{Fat, Region};
use crate::storage::runidx::RunIndex;
use crate::storage::sd::SdCard;

type Card = Mutex<CriticalSectionRawMutex, SdCard<'static>>;
type Index = Mutex<CriticalSectionRawMutex, RunIndex>;

const CBW_SIG: u32 = 0x4342_5355;
const CSW_SIG: u32 = 0x5342_5355;
const MAX_PKT: usize = 64;

fn u32be(b: &[u8]) -> u32 {
    ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | b[3] as u32
}

/// Serve MSC forever on the given bulk endpoints. Runs alongside `usb.run()`.
pub async fn serve<EIN: EndpointIn, EOUT: EndpointOut>(
    ep_in: &mut EIN,
    ep_out: &mut EOUT,
    card: &'static Card,
    index: &'static Index,
) -> ! {
    ep_out.wait_enabled().await;
    let mut cbw = [0u8; 31];
    loop {
        // ── Command Block Wrapper ──
        let n = match ep_out.read(&mut cbw).await {
            Ok(n) => n,
            Err(_) => continue,
        };
        if n < 31 || u32::from_le_bytes([cbw[0], cbw[1], cbw[2], cbw[3]]) != CBW_SIG {
            continue;
        }
        let tag = &cbw[4..8];
        let op = cbw[15];
        let mut status = 0u8; // 0 = good, 1 = failed
        let mut residue: u32 = u32::from_le_bytes([cbw[8], cbw[9], cbw[10], cbw[11]]);

        match op {
            0x12 => {
                // INQUIRY: 36-byte standard data.
                let mut d = [0u8; 36];
                d[0] = 0x00; // direct-access block device
                d[1] = 0x80; // removable
                d[2] = 0x04; // SPC-2
                d[3] = 0x02;
                d[4] = 31; // additional length
                d[8..16].copy_from_slice(b"Sonde   ");
                d[16..32].copy_from_slice(b"Capture SD      ");
                d[32..36].copy_from_slice(b"1.0 ");
                send(ep_in, &d).await;
                residue = residue.saturating_sub(d.len() as u32);
            }
            0x25 => {
                // READ CAPACITY(10): last LBA + block length, big-endian.
                let total = { Fat::new(&index.lock().await.runs).total_blocks() };
                let mut d = [0u8; 8];
                d[0..4].copy_from_slice(&(total - 1).to_be_bytes());
                d[4..8].copy_from_slice(&512u32.to_be_bytes());
                send(ep_in, &d).await;
                residue = residue.saturating_sub(8);
            }
            0x28 => {
                // READ(10).
                let lba = u32be(&cbw[17..21]);
                let count = ((cbw[22] as u32) << 8) | cbw[23] as u32;
                let fat = Fat::new(&index.lock().await.runs);
                let mut block = [0u8; 512];
                for i in 0..count {
                    match fat.locate(lba + i) {
                        Region::Synthetic => fat.synth(lba + i, &mut block),
                        Region::Card(clba) => {
                            let mut c = card.lock().await;
                            if c.read_block(clba, &mut block).await.is_err() {
                                block.fill(0);
                            }
                        }
                    }
                    send(ep_in, &block).await;
                }
                residue = residue.saturating_sub(count * 512);
            }
            0x1A => {
                // MODE SENSE(6): 4-byte header, write-protect bit set (read-only).
                let d = [3u8, 0, 0x80, 0];
                send(ep_in, &d).await;
                residue = residue.saturating_sub(4);
            }
            0x03 => {
                // REQUEST SENSE: fixed format, "no sense".
                let mut d = [0u8; 18];
                d[0] = 0x70;
                d[7] = 10;
                send(ep_in, &d).await;
                residue = residue.saturating_sub(18);
            }
            0x00 | 0x1E => {
                // TEST UNIT READY / PREVENT-ALLOW MEDIUM REMOVAL: status only.
            }
            0x2A | 0x2F => {
                // WRITE(10) / VERIFY: refuse — the volume is read-only.
                status = 1;
            }
            _ => {
                status = 1;
            }
        }

        // ── Command Status Wrapper ──
        let mut csw = [0u8; 13];
        csw[0..4].copy_from_slice(&CSW_SIG.to_le_bytes());
        csw[4..8].copy_from_slice(tag);
        csw[8..12].copy_from_slice(&residue.to_le_bytes());
        csw[12] = status;
        let _ = ep_in.write(&csw).await;
    }
}

/// Write `data` to the bulk-IN endpoint in max-packet chunks.
async fn send<EIN: EndpointIn>(ep_in: &mut EIN, data: &[u8]) {
    let mut off = 0;
    while off < data.len() {
        let end = (off + MAX_PKT).min(data.len());
        if ep_in.write(&data[off..end]).await.is_err() {
            return;
        }
        off = end;
    }
}

/// Concrete driver alias so the binder can name the USB type in one place.
pub type UsbDriver = Driver<'static, HardwareVbusDetect>;
