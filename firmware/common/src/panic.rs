//! Crash reporting: record panics and hard faults to flash, print them on the
//! next boot.
//!
//! A panic used to be indistinguishable from a wedged radio. `panic_probe`
//! prints through RTT, which nothing reads without a debugger attached, and then
//! executes `udf` — HardFault, and cortex-m-rt's default handler is an infinite
//! loop. The capture just stops, exactly like the `follow_aux` busy-wait did (see
//! DESIGN-NOTES §4), with nothing to distinguish the two. This module makes the
//! difference visible: the crash site goes to flash, the LED says a crash
//! happened, and the next boot prints the record into the log.
//!
//! On a crash the site is recorded to flash, the red LED blinks a short burst so
//! a watcher sees it happened, and the device resets. The reset advances the
//! boot-mode rotation ([`crate::next_boot_mode`]), so a mode that crashes
//! deterministically is stepped past rather than retried in a tight loop, and the
//! recorded site is printed on the next boot by [`report_and_clear`].

use core::sync::atomic::{compiler_fence, Ordering};

use embassy_nrf::pac;
use embassy_nrf::pac::nvmc::vals;

/// Crash-record page: the 4 KB page directly above the boot-mode store, and like
/// it, outside the `FLASH` region in `memory.x` so the flasher never touches it.
const PANIC_PAGE: u32 = 0x000E_D000;
const PANIC_PAGE_LEN: u32 = embassy_nrf::nvmc::PAGE_SIZE as u32; // 4096

/// One record. Erased flash reads `0xFFFF_FFFF`, so `magic` in word 0 is what
/// separates a written record from free space.
///
/// | offset | field |
/// |---|---|
/// | 0..4    | [`MAGIC`] |
/// | 4..8    | line number, or the faulting PC for a hard fault |
/// | 8..72   | source file, NUL-padded |
/// | 72..128 | panic message, NUL-padded |
const REC_LEN: usize = 128;
const REC_FILE: usize = 8;
const REC_FILE_LEN: usize = 64;
const REC_MSG: usize = 72;
const REC_MSG_LEN: usize = 56;
const MAGIC: u32 = 0x504E_4321; // "PN!"
const RECS: usize = (PANIC_PAGE_LEN as usize) / REC_LEN;

// ── Recording ─────────────────────────────────────────────────────────────────

/// A `core::fmt::Write` sink that truncates instead of failing.
///
/// The panic message is formatted through this because a panic handler that can
/// itself panic is worse than no panic handler: the second panic re-enters here
/// and the recursion is the only thing that gets recorded.
struct Trunc<'a> {
    buf: &'a mut [u8],
    n: usize,
}

impl core::fmt::Write for Trunc<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let take = (self.buf.len() - self.n).min(s.len());
        self.buf[self.n..self.n + take].copy_from_slice(&s.as_bytes()[..take]);
        self.n += take;
        Ok(())
    }
}

/// Copy the *tail* of `src` into `dst`. The tail of a path is the part that
/// identifies the file; the head is whatever prefix the build happened to use.
fn copy_tail(dst: &mut [u8], src: &[u8]) {
    let take = dst.len().min(src.len());
    dst[..take].copy_from_slice(&src[src.len() - take..]);
}

/// Spin until NVMC reports the flash idle. Bounded for the same reason every
/// other wait in this firmware is: a handler that hangs here records nothing and
/// looks precisely like the fault it was added to explain.
fn nvmc_ready() {
    for _ in 0..1_000_000u32 {
        if pac::NVMC.ready().read().ready() {
            return;
        }
    }
}

/// Append a record to the crash page, erasing it first if it is full.
///
/// Raw `pac::NVMC` rather than the `Nvmc` HAL driver: there is no `Peri` handle
/// to be had from a panic handler, and by this point exclusive access is not in
/// question — interrupts are off and this function does not return.
fn record(line: u32, file: &[u8], msg: &[u8]) {
    let mut rec = [0u8; REC_LEN];
    rec[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    rec[4..8].copy_from_slice(&line.to_le_bytes());
    copy_tail(&mut rec[REC_FILE..REC_FILE + REC_FILE_LEN], file);
    copy_tail(&mut rec[REC_MSG..REC_MSG + REC_MSG_LEN], msg);

    // First free slot, by the same append-log scheme the boot-mode page uses.
    let mut slot = None;
    for i in 0..RECS {
        let w = unsafe { core::ptr::read_volatile((PANIC_PAGE as usize + i * REC_LEN) as *const u32) };
        if w == 0xFFFF_FFFF {
            slot = Some(i);
            break;
        }
    }

    let n = pac::NVMC;
    let slot = match slot {
        Some(s) => s,
        None => {
            n.config().write(|w| w.set_wen(vals::Wen::Een));
            nvmc_ready();
            n.erasepage().write_value(PANIC_PAGE);
            nvmc_ready();
            0
        }
    };

    n.config().write(|w| w.set_wen(vals::Wen::Wen));
    nvmc_ready();
    let base = PANIC_PAGE as usize + slot * REC_LEN;
    for (i, chunk) in rec.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        unsafe { core::ptr::write_volatile((base + i * 4) as *mut u32, word) };
        nvmc_ready();
    }
    n.config().write(|w| w.set_wen(vals::Wen::Ren));
    nvmc_ready();
    compiler_fence(Ordering::SeqCst);
}

/// Blink the onboard red LED a short burst, then reset. The record is already in
/// flash; the burst tells someone looking at the device — rather than at the log
/// — that it crashed, and the reset lets the capture recover on its own (the next
/// boot prints the record and rotates to the next mode).
///
/// Onboard RGB is active-LOW on the XIAO nRF52840; red is P0.26.
fn blink_then_reset() -> ! {
    use pac::gpio::regs::{Dirset, Outclr, Outset};
    const RED: u32 = 1 << 26;
    let p0 = pac::P0;
    p0.dirset().write_value(Dirset(RED));
    // Six blinks (~1.5 s) is long enough to catch the eye without holding the
    // device off-air; the authoritative report is the next boot's log line.
    for _ in 0..6 {
        p0.outclr().write_value(Outclr(RED)); // on
        cortex_m::asm::delay(8_000_000); // ~125 ms at 64 MHz
        p0.outset().write_value(Outset(RED)); // off
        cortex_m::asm::delay(8_000_000);
    }
    cortex_m::peripheral::SCB::sys_reset()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    cortex_m::interrupt::disable();

    let (file, line) = match info.location() {
        Some(l) => (l.file().as_bytes(), l.line()),
        None => (&b"?"[..], 0),
    };

    let mut msg = [0u8; REC_MSG_LEN];
    let mut w = Trunc { buf: &mut msg, n: 0 };
    let _ = core::fmt::write(&mut w, format_args!("{}", info.message()));
    let n = w.n;

    record(line, file, &msg[..n]);
    blink_then_reset()
}

/// A hard fault is as silent as a panic and arrives by different routes — a bad
/// EasyDMA pointer, a stack overflow, an unaligned access — so it is recorded
/// the same way. There is no source location to report, so the faulting PC from
/// the stacked exception frame goes in the line field; look it up against the
/// ELF with `addr2line`.
#[cortex_m_rt::exception]
unsafe fn HardFault(frame: &cortex_m_rt::ExceptionFrame) -> ! {
    cortex_m::interrupt::disable();
    record(frame.pc(), b"HardFault", b"");
    blink_then_reset()
}

// ── Reporting ─────────────────────────────────────────────────────────────────

/// Print every crash record to the log, then wipe the page.
///
/// Called once at boot. Wiping after printing makes the next boot's report mean
/// "crashed since you last looked" instead of replaying old history forever; the
/// history itself lives in the capture files, which is where it is searchable.
///
/// Reads go through the memory-mapped flash directly, so this needs no NVMC
/// handle — only the erase does, and that runs at most once per crash.
/// Invoke `f(file, line, msg)` for each stored crash record; returns the count.
/// Reads go through memory-mapped flash, so no NVMC handle is needed.
fn for_each_record(mut f: impl FnMut(&str, u32, &str)) -> usize {
    let mut found = 0;
    for i in 0..RECS {
        let base = PANIC_PAGE as usize + i * REC_LEN;
        let magic = unsafe { core::ptr::read_volatile(base as *const u32) };
        if magic != MAGIC {
            break;
        }
        let rec = unsafe { core::slice::from_raw_parts(base as *const u8, REC_LEN) };
        let line = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
        let file = trim(&rec[REC_FILE..REC_FILE + REC_FILE_LEN]);
        let msg = trim(&rec[REC_MSG..REC_MSG + REC_MSG_LEN]);
        f(file, line, msg);
        found += 1;
    }
    found
}

/// Erase the crash page. Call once the records have been reported or persisted.
pub fn clear() {
    let n = pac::NVMC;
    n.config().write(|w| w.set_wen(vals::Wen::Een));
    nvmc_ready();
    n.erasepage().write_value(PANIC_PAGE);
    nvmc_ready();
    n.config().write(|w| w.set_wen(vals::Wen::Ren));
    nvmc_ready();
}

/// Print every crash record to the log, then wipe the page (USB-console build).
pub fn report_and_clear() {
    // Count first without emitting — nothing should reach the log before the delay.
    let found = for_each_record(|_, _, _| {});
    if found == 0 {
        return;
    }
    // The reboot-on-panic reset re-enumerated USB. Give the host time to notice the
    // new serial device and start polling it *before* we emit anything, so the crash
    // report is not written into a tty no one is reading yet.
    cortex_m::asm::delay(192_000_000); // ~3 s at 64 MHz
    for_each_record(|file, line, msg| {
        crate::ulogf!("PANIC on a previous boot: {}:{} {}\r\n", file, line, msg);
    });
    clear();
}

/// Format all crash records into `out` as text lines; returns bytes written (0 if
/// none). Does NOT clear — the caller persists the text, then calls [`clear`]. For
/// builds with no console (headless SD capture) that store crashes elsewhere.
pub fn read_records_text(out: &mut [u8]) -> usize {
    use core::fmt::Write;
    struct Sink<'a> {
        buf: &'a mut [u8],
        n: usize,
    }
    impl core::fmt::Write for Sink<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let take = (self.buf.len() - self.n).min(s.len());
            self.buf[self.n..self.n + take].copy_from_slice(&s.as_bytes()[..take]);
            self.n += take;
            Ok(())
        }
    }
    let mut w = Sink { buf: out, n: 0 };
    for_each_record(|file, line, msg| {
        let _ = write!(w, "PANIC {}:{} {}\r\n", file, line, msg);
    });
    w.n
}

/// The stored bytes as a `str`: NUL padding dropped, and anything that is not
/// valid UTF-8 reported as such rather than risking a panic inside the reporter.
fn trim(b: &[u8]) -> &str {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    core::str::from_utf8(&b[..end]).unwrap_or("<invalid>")
}
