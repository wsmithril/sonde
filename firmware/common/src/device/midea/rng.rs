//! A cryptographically-secure RNG backed by the nRF52840 RNG peripheral (a true
//! random generator with bias correction), exposed through `rand_core` so it can
//! seed the Midea ECDH keypair and AES-CCM nonces.
//!
//! [`crate::Rng`] is a stirred LCG for radio timing jitter — fine for channel
//! shuffling, not for keys. This reads the hardware TRNG directly (the same
//! bare-peripheral style as [`crate::hal::crypto`]); it is single-task use only.
#![allow(dead_code)]

use embassy_nrf::pac;
use p256::elliptic_curve::rand_core::{CryptoRng, RngCore};

pub struct HwRng;

impl HwRng {
    /// Enable bias correction (`CONFIG.DERCEN`) and return a handle.
    pub fn new() -> Self {
        pac::RNG.config().write(|w| w.set_dercen(true));
        Self
    }

    /// Block for one bias-corrected random byte.
    fn byte(&self) -> u8 {
        let r = pac::RNG;
        r.events_valrdy().write_value(0);
        r.tasks_start().write_value(1);
        while r.events_valrdy().read() == 0 {}
        r.events_valrdy().write_value(0);
        let v = r.value().read().value();
        r.tasks_stop().write_value(1);
        v
    }
}

impl Default for HwRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for HwRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for x in dest.iter_mut() {
            *x = self.byte();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), p256::elliptic_curve::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for HwRng {}
