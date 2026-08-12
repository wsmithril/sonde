//! Per-boot capture modes as self-contained types.
//!
//! Each mode is a struct implementing [`Mode`]: it owns its radio loop (`run`) and
//! its private helpers (as methods). Its LED indicator is a separate task in the
//! same module that calls the [`crate::led`] primitives. Only one mode runs per
//! boot; a binary picks the struct for `next_boot_mode`'s choice, spawns its `run`
//! and LED tasks, and is done. Low-level primitives shared across modes live in
//! [`crate::hal`] (radio, CSA#2, hash, crypto); the one thing that differs per
//! *build* — where output goes — is abstracted behind [`CaptureSink`], which the
//! binary supplies.

use core::cell::UnsafeCell;

use embassy_time::Instant;

use crate::Rng;
use crate::led::OnBoardLed;

pub mod ble_sniff;
pub mod conn_follow;
pub mod gatt;
pub mod recon;
pub mod rssi;
pub mod zigbee;

pub use ble_sniff::BleSniff;
pub use conn_follow::ConnFollow;
pub use gatt::GattEnum;
pub use rssi::RssiMonitor;
pub use zigbee::ZigbeeSniff;

/// Renders [`crate::led::LED`] commands onto the LED — the state-colour indicator
/// the active-central modes (GATT, Midea) share. Generic over the backend `L`;
/// called by their `led_control` and `led_task`.
pub async fn drive_indicator<L: OnBoardLed>(led: &mut L) -> ! {
    use crate::led::{Cmd, LED, OFF};
    use embassy_time::Timer;

    let mut cur = OFF;
    // A command that arrived while a blink was running — applied next lap.
    let mut pending: Option<Cmd> = None;

    led.set(cur);
    loop {
        let cmd = match pending.take() {
            Some(c) => c,
            None => LED.wait().await,
        };

        let Cmd::Blink { colour, then, count, on_ms, off_ms } = cmd else {
            cur = match cmd {
                Cmd::Solid(c) => c,
                Cmd::Chan(ch, on) => cur.with(ch, on),
                Cmd::Blink { .. } => unreachable!(),
            };
            led.set(cur);
            continue;
        };

        // The pattern races the next command, so a blink can never delay a state
        // change.
        let pattern = async {
            for _ in 0..count {
                led.set(colour);
                Timer::after_millis(on_ms as u64).await;
                led.set(OFF);
                Timer::after_millis(off_ms as u64).await;
            }
            led.set(then);
        };
        match embassy_futures::select::select(pattern, LED.wait()).await {
            embassy_futures::select::Either::First(()) => cur = then,
            embassy_futures::select::Either::Second(next) => {
                led.set(OFF);
                cur = OFF;
                pending = Some(next);
            }
        }
    }
}

/// A captured frame that carries its own decode. The data flow is
/// **radio → sink → decode → phy output**: a mode hands the frame to the build's
/// [`CaptureSink`], which either runs [`decode_to`] (USB console) or reads the raw
/// PCAP fields (headless SD). Each packet family (BLE advert, connection PDU,
/// 802.15.4 frame) implements this, so decode stays typed and lossless while the
/// sink is one uniform backend.
///
/// [`decode_to`]: Frame::decode_to
pub trait Frame {
    /// Air-start instant — stamps the log line / the PCAP record.
    fn t_air(&self) -> Instant;
    /// Semantic decode of this frame to the text render sink (USB console path).
    fn decode_to<S: crate::Sink>(&self, out: &mut S);
    /// Primary/data channel index (PCAP metadata).
    fn ch(&self) -> u8;
    /// RSSI in dBm (PCAP metadata).
    fn rssi(&self) -> i8;
    /// Whether the frame passed CRC.
    fn crc_ok(&self) -> bool;
    /// Link access address (advertising AA, or the connection's).
    fn access_addr(&self) -> u32;
    /// The raw PDU bytes to store (PCAP payload).
    fn payload(&self) -> &[u8];
}

/// The one output backend a build supplies. A mode stays oblivious to the build:
/// packet-capture modes call [`sink_frame`], text modes (GATT/Midea) call
/// [`sink_text`]. The USB build decodes/prints to its console; the headless build
/// writes PCAP/text to the SD ring — the "decode → phy output" half of the flow.
///
/// [`sink_frame`]: CaptureSink::sink_frame
/// [`sink_text`]: CaptureSink::sink_text
pub trait CaptureSink {
    /// One-time preamble (e.g. a PCAP global header). Default: nothing.
    fn begin(&mut self) {}
    /// A ready-made text line (a decoded GATT/Midea record, or a status line).
    fn sink_text(&mut self, line: &str);
    /// One captured frame — the backend decodes it to the console or PCAP-encodes
    /// it to the SD ring, per the build.
    fn sink_frame<F: Frame>(&mut self, frame: &F);
}

/// Per-boot context: shared entropy + the build's capture sink. Held in a `static`
/// by the binary and passed to the active mode by `&'static` reference — so a mode
/// borrows nothing local and its `run` can be a spawned task.
///
/// Interior mutability is the crate's `UnsafeCell` + `unsafe impl Sync` idiom
/// (§Platform in the design notes): sound because the Embassy thread-mode executor
/// is cooperative and single-threaded, and `rng`/`sink` live in *separate* cells so
/// the two `&mut` a mode holds never alias the same memory.
pub struct Ctx<K: CaptureSink> {
    rng: UnsafeCell<Rng>,
    sink: UnsafeCell<K>,
}

// SAFETY: single-threaded cooperative executor; see the type doc.
unsafe impl<K: CaptureSink> Sync for Ctx<K> {}

impl<K: CaptureSink> Ctx<K> {
    /// Const so a binary can place it in a `static`.
    pub const fn new(rng: Rng, sink: K) -> Self {
        Self { rng: UnsafeCell::new(rng), sink: UnsafeCell::new(sink) }
    }

    /// The shared RNG. Distinct cell from [`sink`](Ctx::sink), so holding both
    /// `&mut` at once is sound.
    #[allow(clippy::mut_from_ref)]
    pub fn rng(&self) -> &mut Rng {
        unsafe { &mut *self.rng.get() }
    }

    /// The build's capture sink. Distinct cell from [`rng`](Ctx::rng).
    #[allow(clippy::mut_from_ref)]
    pub fn sink(&self) -> &mut K {
        unsafe { &mut *self.sink.get() }
    }
}

/// A capture mode: a self-contained type that drives the radio (`run`) from a
/// `&'static` [`Ctx`]. `type Sink` names the one sink this mode's build wires it to,
/// so no per-call generic is needed. The LED indicator is a separate task in the
/// mode's module (it reads shared counters / the [`crate::led::LED`] signal and
/// drives the `led` primitives), spawned alongside `run` by the binary.
///
/// `async fn` in a trait is deliberate: the single-threaded executor never needs a
/// `Send` bound on these futures.
#[allow(async_fn_in_trait)]
pub trait Mode {
    /// The capture sink this mode's build supplies.
    type Sink: CaptureSink;
    /// One-time setup before `run`. Does the mode's own radio config (ramp, MODE),
    /// and `await`s `setup` — a **build-supplied callback** carrying the plumbing
    /// that differs per binary and can't live in this shared crate: the USB build
    /// maps the QSPI asset window and spawns provisioning / the LED task; the
    /// headless build spawns its SD ring consumer / LED task. The mode stays
    /// oblivious to which — it just runs the callback its binary handed it.
    async fn init<F: core::future::Future<Output = ()>>(
        &mut self,
        ctx: &'static Ctx<Self::Sink>,
        setup: F,
    );
    /// The mode's endless capture loop.
    async fn run(&mut self, ctx: &'static Ctx<Self::Sink>) -> !;
    /// Render this mode's LED semantics onto `led`, forever. Associated (no `self`)
    /// so it can run concurrently with `run` without aliasing. The mode module also
    /// exposes a concrete `led_task(Pwm)` that delegates here, for spawning.
    async fn led_control<L: OnBoardLed>(led: &mut L) -> !;
}
