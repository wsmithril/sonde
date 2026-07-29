//! LED indication: the board-agnostic colour model and the sink traits the
//! capture modes drive, plus the [`LED`] command signal for the GATT indicator.
//!
//! The *hardware* backend is per board and lives in the binary crate: the USB
//! build (XIAO) has a three-channel RGB backend (`usb/src/led.rs`) and the
//! headless build (nice!nano) a single mono LED (`headless/src/led.rs`). Shared
//! capture code — [`crate::conn_follow`], [`crate::zb_sniff`], [`crate::rssi`] —
//! never names a concrete LED; it takes an `impl` of [`Sink`] / [`ChanSink`], so
//! each build supplies its own indicator (or [`Noop`] to drive the LED elsewhere).
//!
//! GATT mode signals state changes through [`LED`] (a one-slot [`Signal`], so the
//! latest command wins over a stale one); the USB build runs an `indicator` task
//! that renders them. On a build with no consumer the signal is simply ignored.
#![allow(dead_code)]

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

// ── Sink traits ─────────────────────────────────────────────────────────────

/// A colour sink: render a whole [`Rgb`]. The mode code drives this without
/// knowing whether the backend is RGB PWM, RGB GPIO, or a single mono LED.
pub trait Sink {
    fn set(&mut self, c: Rgb);
}

/// A colour sink that can also flip one channel without disturbing the others —
/// what [`crate::conn_follow`] uses to overlay per-direction state on one LED.
pub trait ChanSink: Sink {
    fn set_chan(&mut self, ch: Chan, on: bool);
}

/// A sink that drives nothing — for a build that indicates via another path
/// (e.g. the headless mono LED flashes from the capture-queue consumers, not
/// from inside the mode code).
pub struct Noop;

impl Sink for Noop {
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
