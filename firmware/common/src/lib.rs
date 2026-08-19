#![no_std]

//! Shared library for the Sonde firmware builds (`sonde-usb`, `sonde-headless`).
//!
//! Everything the mode logic needs lives here: the capture modes (`mode::`, one
//! self-contained module per boot mode), the shared low-level primitives they build
//! on (`hal::` — radio, CSA#2, hash, crypto), the decoders, and the shared prelude
//! below (the log channel + macros, `SyncBuf`, `Rng`). Each binary crate supplies
//! the pieces that differ — the USB CDC console vs. the SD PCAP sink — plus its own
//! `#[embassy_executor::main]`, interrupt bindings and peripheral setup.

use core::cell::UnsafeCell;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::Instant;

pub mod decoder;

// ── Serial log channel ────────────────────────────────────────────────────────
//
// ulog!("literal")   → static string, zero allocation
// ulogf!("fmt {}", v) → formatted into a LogLine, then queued
//
// try_send never blocks; messages are silently dropped when the channel is
// full (e.g. USB not connected yet, or host too slow to drain).

/// Capacity of one queued log line. Sized for the widest producer: the RSSI
/// sweep emits all NUM_LEDS values on one line (64 × "-103" + separators ≈ 328 B).
pub const LOG_LINE_CAP: usize = 512;

/// Fixed-capacity log line — the item type of [`LOG`].
pub type LogLine = heapless::String<LOG_LINE_CAP>;

// Depth 192 (≈100 KB): one ext-adv + aux decode fans out ~9 lines in a burst,
// and a crowded channel visit stacks several of those before the drain task is
// scheduled at all. At depth 32 every sniff capture lost ~10% of its lines
// (10,353 of 109,279 in one 43 s run) — the drain task is not slow on average
// once it packs full packets, it is just never given the CPU during a burst,
// and depth is what carries a burst across to the next yield. The cost is bss,
// which sniff mode has: 192 × (Instant + String<512>) against 256 KB of RAM.
//
// Each line carries the [`Instant`] it was *queued*, not the instant it reaches
// the host. Timestamping in the drain task instead — as this did originally —
// silently reports USB scheduling latency as event time: any producer that
// busy-polls the radio (the connection follower spends whole 30 ms intervals
// not yielding) starves the writer, so lines emerge in bursts and a log that
// looks like "one event every 60 ms" is really "24 events, drained whenever".
// That artifact is indistinguishable from a real timing bug, which is exactly
// the kind of bug this log exists to find.
pub static LOG: Channel<CriticalSectionRawMutex, (Instant, LogLine), 192> = Channel::new();

/// Timestamp applied to queued lines while a [`with_log_stamp`] guard is active.
/// `None` outside a guard, where lines carry the instant they were queued.
struct StampCell(UnsafeCell<Option<Instant>>);
unsafe impl Sync for StampCell {}
static LOG_STAMP: StampCell = StampCell(UnsafeCell::new(None));

/// Replace every control character in `s` with `.`, keeping the trailing CRLF.
///
/// Log lines quote text straight off the air — device names, URIs, ATT string
/// values — and a name is an arbitrary byte string that the advertiser chose.
/// One of those bytes being 0x13 (DC3/XOFF) stops the capture dead: the host
/// tty's `IXON` line discipline consumes it as flow control, so nothing more
/// reaches `tio`, no XOFF appears in the file to explain it, and the log just
/// ends mid-scan while the firmware runs on. 0x11 (XON), 0x1B (ESC, and with it
/// every ANSI escape sequence) and the C1 controls a UTF-8 name can encode are
/// the same class of hazard aimed at the terminal instead of the flow.
///
/// Applied here rather than at each of the ~20 decoders that quote text, so a
/// new decoder cannot reintroduce it.
fn sanitize_line(s: &mut LogLine) {
    // SAFETY: every write below either replaces a single ASCII byte, or both
    // bytes of a two-byte C1 sequence, with ASCII `.` — UTF-8 stays valid.
    let b = unsafe { s.as_mut_vec() };
    // The terminator this function must not eat; body is everything before it.
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b'\r' || b[end - 1] == b'\n') {
        end -= 1;
    }
    let mut i = 0;
    while i < end {
        if b[i] < 0x20 || b[i] == 0x7F {
            // Includes CR and LF: a newline inside a name would otherwise split
            // one record into two, and the second would carry no timestamp.
            b[i] = b'.';
        } else if b[i] == 0xC2 && i + 1 < end && (0x80..=0x9F).contains(&b[i + 1]) {
            // U+0080..U+009F — C1 controls, of which 0x9B is CSI.
            b[i] = b'.';
            b[i + 1] = b'.';
            i += 1;
        }
        i += 1;
    }
}

/// Queue a pre-built line, stamped with the current instant — or, inside a
/// [`with_log_stamp`] guard, with that guard's instant. Returns immediately,
/// dropping the line when the channel is full.
pub fn log_send(mut s: LogLine) {
    sanitize_line(&mut s);
    let t = unsafe { *LOG_STAMP.0.get() }.unwrap_or_else(Instant::now);
    if LOG.try_send((t, s)).is_err() {
        LOG_DROPPED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        ERR_TOTAL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// A destination for rendered decode text — one already-terminated line at a
/// time. `Decoded::write_text_to` drives it, so decoding produces a parsed result
/// that any build can render where it wants: the USB build to the CDC console
/// ([`LogSink`] → the [`LOG`] channel), the headless build to an SD text run, a
/// future JSON exporter, etc. Rendering runs in the decode task, never on the
/// radio path, and a sink must not block (the radio-first rule, DESIGN-NOTES §4).
pub trait Sink {
    fn line(&mut self, s: &str);
}

/// The default sink: forward each line to the [`LOG`] channel, stamped by the
/// active [`with_log_stamp`] guard — i.e. exactly the pre-sink behaviour, so the
/// `drain_log`/`text_to_ring` consumers are unchanged.
pub struct LogSink;

impl Sink for LogSink {
    fn line(&mut self, s: &str) {
        let mut l = LogLine::new();
        let _ = l.push_str(s);
        log_send(l);
    }
}

/// Lines discarded because [`LOG`] was full, reported by `drain_log` as soon
/// as it has the endpoint to say so.
///
/// A burst that outruns the host turns the log silent, which reads exactly like
/// a wedged device: the producer never blocks, so the firmware runs on happily
/// while nothing comes out. The count is what tells the two apart.
pub static LOG_DROPPED: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Everything that means the probe lost data: a dropped log line, a full decode
/// queue, a torn DMA snapshot.
///
/// One counter rather than several because its consumer — the USB build's
/// sniff-mode LED indicator — asks one question, did anything go wrong since the
/// last tick, and the log already carries the breakdown for anyone who needs it.
///
/// A radio found still running where DISABLED was expected is *not* counted here:
/// [`hal::radio::ensure_disabled`] recovers it in place with no data lost, so
/// it belongs in [`RADIO_RECOVERED`], not in the loss signal that flashes the LED.
pub static ERR_TOTAL: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Times the radio was found still running where DISABLED was expected and
/// [`hal::radio::ensure_disabled`] disabled it in place. Each one is a benign
/// recovery, not lost data — separate from [`ERR_TOTAL`] so a self-healing quirk
/// does not read as loss. Surfaced per-window as `recovered=` in the sniff stats.
pub static RADIO_RECOVERED: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Stamp every line `f` emits with `t`.
///
/// The sniffer decodes packets in a task separate from the one that captures
/// them, so a packet's lines are formatted some time after it aired. `t` is the
/// packet's air time, which is the event the log is a record of; see the note on
/// [`LOG`] for why the stamp belongs at queue time.
///
/// `f` is a plain `FnOnce` on a cooperative executor, so no other task can queue
/// a line between setting the stamp and clearing it.
pub fn with_log_stamp(t: Instant, f: impl FnOnce()) {
    unsafe { *LOG_STAMP.0.get() = Some(t) };
    f();
    unsafe { *LOG_STAMP.0.get() = None };
}

#[macro_export]
macro_rules! ulog {
    ($msg:literal) => {{
        let mut s = $crate::LogLine::new();
        let _ = s.push_str($msg);
        $crate::log_send(s);
    }};
}

#[macro_export]
macro_rules! ulogf {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut s = $crate::LogLine::new();
        let _ = write!(s, $($arg)*);
        $crate::terminate_line(&mut s);
        $crate::log_send(s);
    }};
}

/// Like [`ulogf!`] but routes the line through [`crate::decoder::emit`] — i.e. to
/// the active render [`Sink`](crate::Sink) inside a `write_text_to`, else the LOG
/// channel. For per-packet *decode* output (which belongs to a `Decoded`), as
/// opposed to standalone status lines (which use `ulogf!`/`ulog!`).
#[macro_export]
macro_rules! emitf {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut s = $crate::LogLine::new();
        let _ = write!(s, $($arg)*);
        $crate::decoder::emit(s); // emit terminates the line and routes to the sink
    }};
}

/// Guarantee a log line ends with CRLF, truncating to make room if needed.
///
/// `heapless`'s `write!` drops any fragment that does not fit *in full*, so a
/// line that fills the buffer (e.g. a long ServiceData/UUID128 hex dump) loses
/// its trailing "\r\n" and runs into the next line. Re-append the terminator,
/// evicting trailing chars if the buffer is full. Lines that already end in
/// '\n' are left untouched.
pub fn terminate_line(s: &mut LogLine) {
    if s.as_str().ends_with('\n') {
        return;
    }
    while s.len() > s.capacity() - 2 {
        s.pop();
    }
    let _ = s.push_str("\r\n");
}

/// Hex dump `payload`, 16 bytes per line, offset-prefixed, with a printable-ASCII
/// gutter alongside each row.
///
/// The gutter is what makes device names, UUID strings and ATT text values
/// readable without hand-decoding hex. It is printable ASCII (0x20..0x7E) with
/// `.` elsewhere, not full UTF-8: a hex dump is column-aligned one byte to one
/// character, and a multi-byte UTF-8 sequence cannot occupy one column without
/// breaking that alignment. This is the same choice `xxd` and `hexdump -C` make.
///
/// Short final rows are padded so the gutter starts in the same column on every
/// line of a dump.
/// `base` is the offset `payload[0]` sits at within the record being dumped, so
/// a dump of just the tail a decoder could not account for still labels its rows
/// with the positions they actually occupy.
pub fn hexdump(payload: &[u8], base: usize, indent: usize) {
    use core::fmt::Write;
    let mut off = 0;
    while off < payload.len() {
        let end = (off + 16).min(payload.len());
        let row = &payload[off..end];
        let mut s = LogLine::new();
        for _ in 0..indent {
            let _ = s.push(' ');
        }
        let _ = write!(s, "+{:02}: ", base + off);
        for b in row {
            let _ = write!(s, "{:02X}", b);
        }
        for _ in row.len()..16 {
            let _ = s.push_str("  ");
        }
        let _ = s.push_str("  ");
        for &b in row {
            let _ = s.push(if (0x20..0x7F).contains(&b) { b as char } else { '.' });
        }
        terminate_line(&mut s);
        log_send(s);
        off = end;
    }
}

/// Hex-only dump for payloads with nothing to annotate: 128 bytes to a line
/// instead of [`hexdump`]'s 16, and no ASCII column. Ciphertext has no readable
/// side and no field boundaries to line the offsets up against, and a 251-byte
/// PDU is 16 lines in the annotated form — two of those per connection event
/// overrun the 32-slot LOG channel by themselves.
pub fn hexdump_dense(prefix: &str, payload: &[u8], indent: usize) {
    use core::fmt::Write;
    let mut off = 0;
    while off < payload.len() {
        let end = (off + 128).min(payload.len());
        let mut s = LogLine::new();
        for _ in 0..indent {
            let _ = s.push(' ');
        }
        let _ = write!(s, "{}+{:03}: ", prefix, off);
        for b in &payload[off..end] {
            let _ = write!(s, "{:02X}", b);
        }
        terminate_line(&mut s);
        log_send(s);
        off = end;
    }
}

pub mod boot;
pub(crate) mod blacklist;
pub mod central;
pub mod gnss;
pub mod hal;
pub mod device;
#[cfg(feature = "resolve-identities")]
pub mod keys;
pub mod led;
pub mod mode;
pub mod panic;
pub mod wallclock;

// ── Shared state ──────────────────────────────────────────────────────────────

/// A `Sync` wrapper around a fixed byte array so it can back an EasyDMA buffer in
/// a `static`. The single-radio, single-scanner design means only one task ever
/// touches a given buffer at a time.
pub struct SyncBuf<const N: usize>(pub UnsafeCell<[u8; N]>);
unsafe impl<const N: usize> Sync for SyncBuf<N> {}
impl<const N: usize> SyncBuf<N> {
    pub const fn new() -> Self {
        Self(UnsafeCell::new([0u8; N]))
    }
}
impl<const N: usize> Default for SyncBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ── Jitter PRNG ───────────────────────────────────────────────────────────────
//
// Tiny xorshift32 generator used only to jitter scan timing. Not cryptographic —
// its sole job is to de-alias the scanner's cadence from an advertiser's periodic
// advertising interval. Stirred each cycle with RSSI-noise samples so the sequence
// differs across boots and keeps drifting.
pub struct Rng(pub u32);
impl Rng {
    pub fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }

    /// Value in `0..n` (returns 0 when `n == 0`).
    pub fn below(&mut self, n: u32) -> u32 {
        if n == 0 { 0 } else { self.next_u32() % n }
    }

    /// Fold external entropy (e.g. RSSI noise) into the state.
    /// xorshift dies on an all-zero state, so keep it non-zero.
    pub fn stir(&mut self, entropy: u32) {
        self.0 ^= entropy.rotate_left(7);
        if self.0 == 0 { self.0 = 0x9E37_79B9; }
    }
}
