//! Onboard RGB LED (XIAO nRF52840): the hardware backends and indicator tasks.
//!
//! The XIAO carries one common-anode RGB LED wired to P0.26 (red), P0.30 (green)
//! and P0.06 (blue). Every channel is **active-LOW** — driving the pin low lights
//! it — and every mode uses the same three pins for something different, so the
//! pin map, the polarity and the duty-cycle convention are written down here once.
//!
//! The colour model, the sink traits and the [`Cmd`]/[`LED`] command signal live
//! in `sonde_common::led` and are re-exported here so call sites say `led::…`.
//! Two backends, because the modes do not all want the same thing:
//!
//! * [`Pwm`] — three PWM channels, any of 2^24 gamma-corrected mixes, one
//!   fire-and-forget DMA kick per update (see [`Pwm::set`]).
//! * [`Gpio`] — three plain outputs, the eight corners of the cube, one register
//!   write per channel — the fit for a radio event loop and the boot indicator.
#![allow(dead_code)]

use core::sync::atomic::{Ordering, compiler_fence};

use embassy_nrf::Peri;
use embassy_nrf::gpio::{AnyPin, Level, Output, OutputDrive};
use embassy_nrf::pac;
use embassy_nrf::peripherals::{P0_06, P0_26, P0_30, PWM0};
use embassy_nrf::pwm::{DutyCycle, Prescaler, SimpleConfig, SimplePwm};
use embassy_time::Timer;

pub use sonde_common::led::{
    BLUE, CYAN, Chan, ChanSink, Cmd, GREEN, LED, OFF, RED, Rgb, Sink, WHITE,
};

// ── PWM backend ───────────────────────────────────────────────────────────────

/// PWM period as a `(prescaler, countertop)` pair: 16 MHz / 1 / 1024 = 15.6 kHz.
///
/// The carrier frequency itself does not matter — anything above a few hundred
/// hertz is invisible. The *period* sets how long a new duty takes to appear:
/// [`Pwm::set`] is fire-and-forget, so it no longer gates CPU time, but a loaded
/// duty still takes effect only at the next period boundary. 64 µs here keeps a
/// colour change well inside the 1 ms sniff frame.
const PWM_PRESCALER: Prescaler = Prescaler::Div1;
const PWM_COUNTERTOP: u16 = 1024;

/// The three LEDs on three PWM channels: full 8-bit-per-channel mixing.
pub struct Pwm {
    pwm: SimplePwm<'static>,
    max: u32,
    /// The DMA source the PWM sequencer reads each channel's compare value from.
    /// It lives in the struct — not a `SimplePwm` internal — so [`Pwm::set`] can
    /// reload it and restart the sequence by hand, skipping the busy-wait the
    /// driver's own `set_all_duties` does. Sound because a `Pwm` only ever exists
    /// inside a `'static` task, so this address is fixed for as long as the DMA
    /// reads it.
    duty: [DutyCycle; 4],
}

impl Pwm {
    /// Takes the three pins by their concrete types, so the channel order
    /// (`ch0 = R`, `ch1 = G`, `ch2 = B`) cannot be got wrong at a call site.
    ///
    /// Idle level is High on every channel including the unused ch3: the LEDs are
    /// active-LOW, so idling low would light them whenever the peripheral is
    /// disabled.
    pub fn new(
        pwm0: Peri<'static, PWM0>,
        r: Peri<'static, P0_26>,
        g: Peri<'static, P0_30>,
        b: Peri<'static, P0_06>,
    ) -> Self {
        let mut cfg = SimpleConfig::default();
        cfg.prescaler = PWM_PRESCALER;
        cfg.max_duty = PWM_COUNTERTOP;
        cfg.ch0_idle_level = Level::High;
        cfg.ch1_idle_level = Level::High;
        cfg.ch2_idle_level = Level::High;
        cfg.ch3_idle_level = Level::High;
        let pwm = SimplePwm::new_3ch(pwm0, r, g, b, &cfg);
        let max = pwm.max_duty() as u32;
        Self { pwm, max, duty: [DutyCycle::normal(0); 4] }
    }
}

impl Sink for Pwm {
    /// Renders a colour, in one DMA transfer for all three channels.
    ///
    /// `DutyCycle::normal(v)` drives the pin high once the counter reaches `v`,
    /// so with active-LOW LEDs the lit fraction of each period is `v/max_duty`
    /// — the duty value *is* the brightness, not its complement.
    ///
    /// The channel value is squared on the way through (perceived brightness goes
    /// roughly as the square of duty). Fire-and-forget: this loads the new duties
    /// and kicks the DMA, then returns — it does not busy-wait for
    /// `EVENTS_SEQEND`. Callers space updates ≥1 ms apart while the transfer
    /// completes within one period (~64 µs), so the executor is never held for a
    /// colour change. The new duty takes effect at the next period boundary.
    fn set(&mut self, c: Rgb) {
        let d = |v: u8| DutyCycle::normal((v as u32 * v as u32 * self.max / (255 * 255)) as u16);
        self.duty = [d(c.r), d(c.g), d(c.b), DutyCycle::normal(0)];

        // The same sequence load `SimplePwm::set_all_duties` performs, via raw
        // `pac`, minus the trailing SEQEND busy-wait. `new` is PWM0-only, and
        // seq0's sample count / load mode were set up by `new_3ch` and persist,
        // so only the pointer needs re-aiming.
        let _ = &self.pwm;
        let r = pac::PWM0;
        r.dma().seq(0).ptr().write_value(self.duty.as_ptr() as u32);
        compiler_fence(Ordering::SeqCst);
        r.events_seqend(0).write_value(0);
        r.tasks_dma().seq(0).start().write_value(1);
    }
}

// ── GPIO backend ──────────────────────────────────────────────────────────────

/// The three LEDs as plain outputs: the eight corners of the cube, one register
/// write per channel and no busy-wait — for the boot-mode indicator (runs before
/// any executor exists) and connection-follow (toggles the LED between events).
pub struct Gpio {
    r: Output<'static>,
    g: Output<'static>,
    b: Output<'static>,
    cur: Rgb,
}

impl Gpio {
    pub fn new(
        r: Peri<'static, P0_26>,
        g: Peri<'static, P0_30>,
        b: Peri<'static, P0_06>,
    ) -> Self {
        // Level::High is off: start dark rather than lighting whatever the pins
        // were left holding.
        let out = |p: Peri<'static, AnyPin>| Output::new(p, Level::High, OutputDrive::Standard);
        Self { r: out(r.into()), g: out(g.into()), b: out(b.into()), cur: OFF }
    }

    /// Takes the pins without going through `Peripherals`, for the boot path that
    /// needs an LED before the mode arm has been chosen and the pins handed out.
    ///
    /// # Safety
    ///
    /// The caller must not hold another handle to P0.26 / P0.30 / P0.06, and must
    /// drop this one before the mode arm claims them from `Peripherals`.
    pub unsafe fn steal() -> Self {
        unsafe { Self::new(P0_26::steal(), P0_30::steal(), P0_06::steal()) }
    }

    /// Turns one channel on or off and leaves the other two alone.
    pub fn set_chan_(&mut self, ch: Chan, on: bool) {
        let lvl = if on { Level::Low } else { Level::High };
        match ch {
            Chan::R => self.r.set_level(lvl),
            Chan::G => self.g.set_level(lvl),
            Chan::B => self.b.set_level(lvl),
        }
        self.cur = self.cur.with(ch, on);
    }

    /// Whether a channel is currently lit — so a caller tracking its own copy of
    /// the state does not have to.
    pub fn is_on(&self, ch: Chan) -> bool {
        self.cur.chan(ch) != 0
    }
}

impl Sink for Gpio {
    /// Lights every channel of `c` that is non-zero. Intensity is discarded — a
    /// dimmed colour and a full one look identical here.
    fn set(&mut self, c: Rgb) {
        // Active-LOW: Level::Low = lit.
        let lvl = |v: u8| if v != 0 { Level::Low } else { Level::High };
        self.r.set_level(lvl(c.r));
        self.g.set_level(lvl(c.g));
        self.b.set_level(lvl(c.b));
        self.cur = c;
    }
}

impl ChanSink for Gpio {
    fn set_chan(&mut self, ch: Chan, on: bool) {
        self.set_chan_(ch, on);
    }
}

// ── Indicator task (GATT) ─────────────────────────────────────────────────────

/// Renders [`LED`] commands onto the onboard RGB LED.
///
/// Used by GATT-central mode, which maps colours onto its own states (scanning →
/// connected → reading → error). Sniff mode runs [`sniff`] on the same hardware
/// instead, and connection-follow drives a [`Gpio`] directly, so at most one of
/// the three is ever spawned.
#[embassy_executor::task]
pub async fn indicator(mut leds: Pwm) -> ! {
    let mut cur = OFF;
    // A command that arrived while a blink was running. It has already been taken
    // out of the signal, so it must be applied on the next lap rather than waited
    // for again.
    let mut pending: Option<Cmd> = None;

    leds.set(cur);
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
            leds.set(cur);
            continue;
        };

        // The pattern races the next command, so a blink can never delay a state
        // change — a connection that starts 40 ms after the target is chosen must
        // not wait out the remaining flashes.
        let pattern = async {
            for _ in 0..count {
                leds.set(colour);
                Timer::after_millis(on_ms as u64).await;
                leds.set(OFF);
                Timer::after_millis(off_ms as u64).await;
            }
            leds.set(then);
        };
        let outcome = embassy_futures::select::select(pattern, LED.wait()).await;
        match outcome {
            embassy_futures::select::Either::First(()) => cur = then,
            embassy_futures::select::Either::Second(next) => {
                // Interrupted mid-flash: the LED may be lit, and the incoming
                // command is applied on the next lap. Leave nothing on in between.
                leds.set(OFF);
                cur = OFF;
                pending = Some(next);
            }
        }
    }
}

// ── Sniff-mode indicator ──────────────────────────────────────────────────────

/// Sniff-mode indicator: the LED is dark, and each packet lights it for a
/// millisecond in a colour that carries the capture rate.
///
/// Three unrelated things share one LED, on separate axes: **liveness** is the
/// blink itself (dark rests, so a stalled capture goes dark); **rate** is the
/// blink's blue→cyan→green colour over an EWMA of packets per second; **loss** is
/// a red frame whenever [`sonde_common::ERR_TOTAL`] moves. The three are ranked,
/// not blended: a loss flash owns its frame, then a packet blink, then dark.
///
/// Nothing on the capture path drives this task — it reads two monotonic counters
/// on its own schedule, so a rate of several hundred packets per second costs the
/// scanner nothing here beyond one `fetch_add`.
#[embassy_executor::task]
pub async fn sniff(mut leds: Pwm) -> ! {
    use core::sync::atomic::Ordering;

    /// Render period, and so also the width of a blink and of a loss flash.
    const FRAME_MS: u64 = 1;
    /// Frames per rate sample (counters read every frame, folded into the EWMA
    /// over a 50 ms window).
    const FRAMES_PER_SAMPLE: u32 = 50;
    /// Top of the scale, in packets per second: blue at nothing, cyan at half,
    /// green at or above.
    const RATE_MAX: u32 = 640;
    /// How much light the green die puts out against the blue one at equal duty,
    /// so the LED holds one apparent brightness and only its hue carries the rate.
    const LUM_G: u32 = 6;
    /// EWMA weight as a right shift: `new = old + (sample - old) >> SHIFT`.
    const EWMA_SHIFT: u32 = 4;

    let mut prev_pkts = sonde_common::ble_sniff::PKT_TOTAL.load(Ordering::Relaxed);
    let mut prev_errs = sonde_common::ERR_TOTAL.load(Ordering::Relaxed);
    // Seeded from the first sample rather than from zero, so the LED does not show
    // the filter climbing to the true rate on entry to sniff mode.
    let mut ewma_q8: Option<i32> = None;

    let mut window: u32 = 0;
    let mut frame: u32 = 0;
    let mut mix = OFF;
    let mut shown = OFF;

    leds.set(shown);
    loop {
        Timer::after_millis(FRAME_MS).await;

        let pkts = sonde_common::ble_sniff::PKT_TOTAL.load(Ordering::Relaxed);
        let arrived = pkts.wrapping_sub(prev_pkts);
        prev_pkts = pkts;
        window += arrived;

        frame += 1;
        let flash = if frame == FRAMES_PER_SAMPLE {
            frame = 0;
            let sample = (window * (1000 / (FRAME_MS as u32 * FRAMES_PER_SAMPLE))) as i32;
            window = 0;
            let e = match ewma_q8 {
                Some(e) => e + (((sample << 8) - e) >> EWMA_SHIFT),
                None => sample << 8,
            };
            ewma_q8 = Some(e);

            let errs = sonde_common::ERR_TOTAL.load(Ordering::Relaxed);
            let moved = errs != prev_errs;
            prev_errs = errs;

            // Position along the fade: 0 is blue, 256 cyan, 512 green.
            let rate = e.max(0) as u32 >> 8;
            let pos = (rate * 512 / RATE_MAX).min(512);
            // Blue at full drive sets the luminance budget; green claims `pos/512`
            // of it and blue the remainder, each square-rooted back through the
            // gamma `Pwm::set` applies — 255² is that full-blue budget.
            let g = (65025 * pos / (512 * LUM_G)).isqrt() as u8;
            let b = (65025 * (512 - pos) / 512).isqrt() as u8;
            mix = Rgb::new(0, g, b);

            moved
        } else {
            false
        };

        // Light the frame a packet landed in. Several packets inside one frame
        // light it once — the blink reports the air is live, the colour the rate.
        let want = if flash {
            RED
        } else if arrived > 0 {
            mix
        } else {
            OFF
        };
        if want != shown {
            leds.set(want);
            shown = want;
        }
    }
}
