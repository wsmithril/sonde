//! Minimal SD-card block driver over SPI (SPIM2), async on `embassy_nrf::Spim`.
//!
//! Implements just what the append log needs: SPI-mode init (CMD0/CMD8/ACMD41/
//! CMD58), single-block read (CMD17) and single-block write (CMD24). SDHC/SDXC
//! (block addressing) and legacy byte-addressed SDSC are both handled. CRCs are
//! sent as the required constants for CMD0/CMD8 and ignored otherwise (SPI CRC is
//! off by default).
//!
//! HARDWARE-UNVERIFIED: written to spec but not yet exercised on a card — SD init
//! timing and card quirks need bench bring-up. Chip-select is driven manually
//! because a shared byte-stream card does not map onto `SpiDevice` cleanly here.

use embassy_nrf::gpio::Output;
use embassy_nrf::spim::Spim;
use embassy_time::{Duration, Timer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NoCard,
    Timeout,
    Cmd(u8),
    Write(u8),
}

pub struct SdCard<'d> {
    spim: Spim<'d>,
    cs: Output<'d>,
    /// SDHC/SDXC address blocks directly; SDSC addresses bytes (lba × 512).
    block_addr: bool,
}

impl<'d> SdCard<'d> {
    pub fn new(spim: Spim<'d>, cs: Output<'d>) -> Self {
        Self { spim, cs, block_addr: true }
    }

    /// Clock `n` idle (0xFF) bytes with CS *deasserted* — the card needs ≥74 such
    /// cycles after power-up before it will enter SPI mode.
    async fn idle_clocks(&mut self, n: usize) {
        self.cs.set_high();
        let ff = [0xFFu8; 16];
        let mut left = n;
        while left > 0 {
            let take = left.min(ff.len());
            let _ = self.spim.write(&ff[..take]).await;
            left -= take;
        }
    }

    /// Transfer one byte (send `b`, return what the card clocked back).
    async fn xfer(&mut self, b: u8) -> u8 {
        let mut buf = [b];
        let _ = self.spim.transfer_in_place(&mut buf).await;
        buf[0]
    }

    /// Send a command frame and return the R1 response (first non-0xFF byte).
    async fn command(&mut self, cmd: u8, arg: u32, crc: u8) -> u8 {
        // A leading dummy byte lets the card finish any prior operation.
        let _ = self.xfer(0xFF).await;
        let frame = [
            0x40 | cmd,
            (arg >> 24) as u8,
            (arg >> 16) as u8,
            (arg >> 8) as u8,
            arg as u8,
            crc,
        ];
        let mut f = frame;
        let _ = self.spim.transfer_in_place(&mut f).await;
        // R1 arrives within 8 bytes; the ready bit (0x80) is clear when valid.
        for _ in 0..8 {
            let r = self.xfer(0xFF).await;
            if r & 0x80 == 0 {
                return r;
            }
        }
        0xFF
    }

    /// Bring the card into SPI mode and read its capacity class.
    pub async fn init(&mut self) -> Result<(), Error> {
        self.idle_clocks(10).await;
        self.cs.set_low();

        // CMD0: go idle (CRC is mandatory here).
        let mut ok = false;
        for _ in 0..10 {
            if self.command(0, 0, 0x95).await == 0x01 {
                ok = true;
                break;
            }
            Timer::after(Duration::from_millis(1)).await;
        }
        if !ok {
            self.cs.set_high();
            return Err(Error::NoCard);
        }

        // CMD8: voltage check; a v2 card echoes 0x1AA in the R7 tail.
        let r = self.command(8, 0x0000_01AA, 0x87).await;
        if r == 0x01 {
            let mut tail = [0xFFu8; 4];
            let _ = self.spim.transfer_in_place(&mut tail).await;
            // tail[3] should echo 0xAA; we accept either way and let ACMD41 decide.
        }

        // ACMD41 with HCS set, until the card leaves idle.
        let mut ready = false;
        for _ in 0..2000 {
            let _ = self.command(55, 0, 0x01).await; // APP_CMD
            if self.command(41, 0x4000_0000, 0x01).await == 0x00 {
                ready = true;
                break;
            }
            Timer::after(Duration::from_millis(1)).await;
        }
        if !ready {
            self.cs.set_high();
            return Err(Error::Timeout);
        }

        // CMD58: read OCR; CCS (bit 30) distinguishes block- from byte-addressed.
        if self.command(58, 0, 0x01).await == 0x00 {
            let mut ocr = [0xFFu8; 4];
            let _ = self.spim.transfer_in_place(&mut ocr).await;
            self.block_addr = ocr[0] & 0x40 != 0;
        }
        if !self.block_addr {
            // CMD16: force a 512-byte block length on a byte-addressed card.
            let _ = self.command(16, 512, 0x01).await;
        }

        self.cs.set_high();
        let _ = self.xfer(0xFF).await;
        Ok(())
    }

    fn addr(&self, lba: u32) -> u32 {
        if self.block_addr { lba } else { lba * 512 }
    }

    /// Read one 512-byte block.
    pub async fn read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), Error> {
        self.cs.set_low();
        let r = self.command(17, self.addr(lba), 0x01).await;
        if r != 0x00 {
            self.cs.set_high();
            return Err(Error::Cmd(r));
        }
        // Wait for the data-start token 0xFE.
        let mut tries = 0;
        loop {
            let t = self.xfer(0xFF).await;
            if t == 0xFE {
                break;
            }
            tries += 1;
            if tries > 20000 {
                self.cs.set_high();
                return Err(Error::Timeout);
            }
        }
        for b in buf.iter_mut() {
            *b = 0xFF;
        }
        let _ = self.spim.transfer_in_place(buf).await;
        let mut crc = [0xFFu8; 2];
        let _ = self.spim.transfer_in_place(&mut crc).await;
        self.cs.set_high();
        let _ = self.xfer(0xFF).await;
        Ok(())
    }

    /// Write one 512-byte block.
    pub async fn write_block(&mut self, lba: u32, buf: &[u8; 512]) -> Result<(), Error> {
        self.cs.set_low();
        let r = self.command(24, self.addr(lba), 0x01).await;
        if r != 0x00 {
            self.cs.set_high();
            return Err(Error::Cmd(r));
        }
        let _ = self.xfer(0xFF).await; // one idle byte before the data packet
        let _ = self.xfer(0xFE).await; // data-start token
        let mut data = *buf;
        let _ = self.spim.transfer_in_place(&mut data).await;
        let mut crc = [0xFFu8; 2];
        let _ = self.spim.transfer_in_place(&mut crc).await;
        // Data-response token: xxx00101 = accepted.
        let resp = self.xfer(0xFF).await;
        if resp & 0x1F != 0x05 {
            self.cs.set_high();
            return Err(Error::Write(resp));
        }
        // Card holds MISO low while it programs; wait for it to release.
        let mut tries = 0;
        while self.xfer(0xFF).await == 0x00 {
            tries += 1;
            if tries > 200000 {
                self.cs.set_high();
                return Err(Error::Timeout);
            }
        }
        self.cs.set_high();
        let _ = self.xfer(0xFF).await;
        Ok(())
    }
}
