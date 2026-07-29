//! A fixed-capacity byte ring between the capture/decode tasks (producers) and the
//! SD writer task (consumer).
//!
//! Modelled on `log_send`: `push` never blocks and drops-and-counts on overflow,
//! so a slow card can never stall the timing-critical radio path. Only one mode
//! runs per boot, so in practice there is a single producer, but access is guarded
//! by a critical section anyway (single-core, cheap) to stay correct if a decode
//! task and a status line ever push concurrently.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

pub struct Ring<const N: usize> {
    buf: UnsafeCell<[u8; N]>,
    /// Monotonic byte counters; the live index is `pos % N`, used = `head - tail`.
    head: UnsafeCell<usize>,
    tail: UnsafeCell<usize>,
    dropped: AtomicU32,
}

unsafe impl<const N: usize> Sync for Ring<N> {}

impl<const N: usize> Ring<N> {
    pub const fn new() -> Self {
        Self {
            buf: UnsafeCell::new([0u8; N]),
            head: UnsafeCell::new(0),
            tail: UnsafeCell::new(0),
            dropped: AtomicU32::new(0),
        }
    }

    /// Append `data`; returns false (and bumps `dropped`) if it does not fit whole.
    pub fn push(&self, data: &[u8]) -> bool {
        cortex_m::interrupt::free(|_| unsafe {
            let head = *self.head.get();
            let tail = *self.tail.get();
            if N - (head - tail) < data.len() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            let buf = &mut *self.buf.get();
            for (k, &b) in data.iter().enumerate() {
                buf[(head + k) % N] = b;
            }
            *self.head.get() = head + data.len();
            true
        })
    }

    /// Copy up to `out.len()` queued bytes into `out`, advancing the read cursor;
    /// returns how many were copied.
    pub fn read(&self, out: &mut [u8]) -> usize {
        cortex_m::interrupt::free(|_| unsafe {
            let head = *self.head.get();
            let tail = *self.tail.get();
            let n = (head - tail).min(out.len());
            let buf = &*self.buf.get();
            for (k, slot) in out.iter_mut().take(n).enumerate() {
                *slot = buf[(tail + k) % N];
            }
            *self.tail.get() = tail + n;
            n
        })
    }
}

impl<const N: usize> Default for Ring<N> {
    fn default() -> Self {
        Self::new()
    }
}
