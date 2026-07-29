//! LED indication for the onboard RGB LED (XIAO nRF52840): the colour model, the
//! sink traits, the [`LED`] command signal, **and** the hardware backends and
//! indicator tasks — one implementation shared by both the USB and headless
//! builds (both target the XIAO, same LED on the same pins).
//!
//! The XIAO carries one common-anode RGB LED on P0.26 (red), P0.30 (green) and
//! P0.06 (blue). Every channel is **active-LOW** (drive the pin low to light it).
//! Two backends, because the modes want different things:
//!
//! * [`Pwm`] — three PWM channels, any of 2^24 gamma-corrected mixes, one
//!   fire-and-forget DMA kick per update (see [`Pwm::set`]).
//! * [`Gpio`] — three plain outputs, the eight corners of the cube, one register
//!   write per channel — the fit for a radio event loop and the boot indicator.
//!
//! Shared capture code — [`crate::mode::conn_follow`], [`crate::mode::zigbee`],
//! [`crate::mode::rssi`] — never names a concrete backend; it takes an `impl` of
//! [`OnBoardLed`] / [`ChanSink`] (or [`Noop`] to drive the LED elsewhere). GATT mode
//! signals state changes through [`LED`]; the [`indicator`] task renders them.
#![allow(dead_code)]

use core::sync::atomic::{Ordering, compiler_fence};

use embassy_nrf::gpio::{AnyPin, Level, Output, OutputDrive};
use embassy_nrf::pac;
use embassy_nrf::peripherals::{P0_06, P0_26, P0_30, PWM0};
use embassy_nrf::pwm::{DutyCycle, Prescaler, SimpleConfig, SimplePwm};
use embassy_nrf::Peri;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

// ── Colour ────────────────────────────────────────────────────────────────────

/// One of the three physical LEDs, for the calls that address a single channel.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Chan {
    R,
    G,
    B,
}

/// A colour as three 8-bit channel intensities, 0 = off and 255 = full.
///
/// A GPIO backend can only render 0 or non-zero per channel, so a mix sent there
/// lands on the nearest corner of the cube; a PWM backend renders all 256 levels;
/// a mono backend lights on any non-zero channel.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

/// The eight corners of the colour cube, at full intensity. Anything between
/// them is built with [`Rgb::new`], [`Rgb::dim`] or [`Rgb::mix`].
pub const OFF: Rgb = Rgb::new(0, 0, 0);
pub const RED: Rgb = Rgb::new(255, 0, 0);
pub const GREEN: Rgb = Rgb::new(0, 255, 0);
pub const BLUE: Rgb = Rgb::new(0, 0, 255);
pub const YELLOW: Rgb = Rgb::new(255, 255, 0);
pub const CYAN: Rgb = Rgb::new(0, 255, 255);
pub const MAGENTA: Rgb = Rgb::new(255, 0, 255);
pub const WHITE: Rgb = Rgb::new(255, 255, 255);

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// This colour at `num/den` of its intensity.
    pub const fn dim(self, num: u16, den: u16) -> Self {
        Self {
            r: (self.r as u16 * num / den) as u8,
            g: (self.g as u16 * num / den) as u8,
            b: (self.b as u16 * num / den) as u8,
        }
    }

    /// Linear crossfade: `t = 0` is all `self`, `t = 256` is all `other`.
    ///
    /// The interpolation is in *duty* space, before any gamma a PWM backend
    /// applies — mixing two colours the eye has already been corrected for would
    /// apply the curve twice and pull the midpoint dark.
    pub fn mix(self, other: Rgb, t: u32) -> Self {
        let t = if t > 256 { 256 } else { t };
        let lerp = |a: u8, b: u8| ((a as u32 * (256 - t) + b as u32 * t) >> 8) as u8;
        Self {
            r: lerp(self.r, other.r),
            g: lerp(self.g, other.g),
            b: lerp(self.b, other.b),
        }
    }

    /// This colour with one channel forced fully on or fully off, the other two
    /// left as they are.
    pub const fn with(self, ch: Chan, on: bool) -> Self {
        let v = if on { 255 } else { 0 };
        match ch {
            Chan::R => Self { r: v, ..self },
            Chan::G => Self { g: v, ..self },
            Chan::B => Self { b: v, ..self },
        }
    }

    pub const fn chan(self, ch: Chan) -> u8 {
        match ch {
            Chan::R => self.r,
            Chan::G => self.g,
            Chan::B => self.b,
        }
    }
}

// ── OnBoardLed traits ─────────────────────────────────────────────────────────────

/// A colour sink: render a whole [`Rgb`]. The mode code drives this without
/// knowing whether the backend is RGB PWM, RGB GPIO, or a single mono LED.
pub trait OnBoardLed {
    fn set(&mut self, c: Rgb);
}

/// A colour sink that can also flip one channel without disturbing the others —
/// what [`crate::mode::conn_follow`] uses to overlay per-direction state on one LED.
pub trait ChanSink: OnBoardLed {
    fn set_chan(&mut self, ch: Chan, on: bool);
}

/// A sink that drives nothing — for a build that indicates via another path
/// (e.g. the headless mono LED flashes from the capture-queue consumers, not
/// from inside the mode code).
pub struct Noop;

impl OnBoardLed for Noop {
    fn set(&mut self, _c: Rgb) {}
}
impl ChanSink for Noop {
    fn set_chan(&mut self, _ch: Chan, _on: bool) {}
}

// ── Commands (GATT indicator) ─────────────────────────────────────────────────

/// What the RGB `indicator` task should do next. Delivered through [`LED`], which
/// holds one command: a signal arriving before the previous one is consumed
/// replaces it, so the LED converges on the most recent state rather than
/// replaying a backlog of stale ones.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    /// Light this colour and hold it until something else arrives.
    Solid(Rgb),
    /// Turn one channel on or off, leaving the other two as they are.
    Chan(Chan, bool),
    /// Flash `colour` `count` times, `on_ms` lit and `off_ms` dark per flash,
    /// then settle on `then`.
    Blink {
        colour: Rgb,
        then: Rgb,
        count: u16,
        on_ms: u16,
        off_ms: u16,
    },
}

impl Cmd {
    /// How long this command takes to finish, in milliseconds; 0 for the ones
    /// that are a single write.
    pub fn total_ms(self) -> u64 {
        match self {
            Cmd::Blink { count, on_ms, off_ms, .. } => {
                count as u64 * (on_ms as u64 + off_ms as u64)
            }
            _ => 0,
        }
    }
}

/// The channel from any task to the RGB `indicator`.
pub static LED: Signal<CriticalSectionRawMutex, Cmd> = Signal::new();

/// Light a solid colour until something replaces it.
pub fn solid(c: Rgb) {
    LED.signal(Cmd::Solid(c));
}

/// Turn one channel on or off without disturbing the other two.
pub fn chan(ch: Chan, on: bool) {
    LED.signal(Cmd::Chan(ch, on));
}

/// Flash `colour` `count` times at `on_ms`/`off_ms`, then go dark. Returns how
/// long the pattern runs, so the caller can `Timer::after_millis(..)` it out if
/// the flashes matter.
pub fn blink(colour: Rgb, count: u16, on_ms: u16, off_ms: u16) -> u64 {
    blink_then(colour, OFF, count, on_ms, off_ms)
}

/// [`blink`], but settling on `then` instead of going dark — for a state change
/// that wants to announce itself and then stay visible.
pub fn blink_then(colour: Rgb, then: Rgb, count: u16, on_ms: u16, off_ms: u16) -> u64 {
    let cmd = Cmd::Blink { colour, then, count, on_ms, off_ms };
    LED.signal(cmd);
    cmd.total_ms()
}

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

impl OnBoardLed for Pwm {
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

impl OnBoardLed for Gpio {
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

/// No-SD / fatal indication: steal the RGB pins and blink red forever. Shown on a
/// path where the executor may not be running (before or instead of a task), so it
/// busy-waits rather than awaiting a timer.
///
/// # Safety-ish
///
/// Steals P0.26/P0.30/P0.06 even if a backend already holds them — acceptable only
/// because this never returns: the board is wedged and the LED is the last word.
pub fn fatal_blink() -> ! {
    let mut leds = unsafe { Gpio::steal() };
    loop {
        leds.set(RED);
        cortex_m::asm::delay(8_000_000);
        leds.set(OFF);
        cortex_m::asm::delay(8_000_000);
    }
}

// ── Indicator task (GATT) ─────────────────────────────────────────────────────

