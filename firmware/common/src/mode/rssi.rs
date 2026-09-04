//! RSSI spectrum sweep and its WS2812 visualisation (RSSI-monitor boot mode).
//!
//! Each sweep samples RSSI across the 2.4 GHz band at [`NUM_LEDS`] evenly-spaced
//! points, converts each reading to linear power, smooths it, and renders the
//! 6×10 WS2812 matrix as **10 band columns** — each column one ~7.8 MHz stripe
//! of the band, every LED in one of five discrete strength levels (off / red /
//! amber / green / white) so neighbouring bands read as distinct cells. The
//! raw per-point magnitudes are logged as one `RSSI [v0,…,vN]` line per sweep,
//! the onboard RGB LED shows the (smoothed) band average, and the noise-floor
//! entropy is folded into the shared jitter PRNG (see [`crate::Rng`]).

use core::cell::UnsafeCell;
use core::future::pending;
use core::marker::PhantomData;

use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;
use embassy_nrf::spim::Spim;
use embassy_time::Timer;

use super::{Ctx, Mode, ModeRef};
use crate::hal::radio::ensure_disabled;
use crate::led::{OnBoardLed, Pwm};
use crate::{Rng, SyncBuf, log_send};

// ── Strip configuration ───────────────────────────────────────────────────────

// The Seeed 6×10 RGB matrix: 10 columns × 6 rows of WS2812 in one serpentine
// chain (row 0 left→right, row 1 right→left, …). Each matrix column shows one
// ~7.8 MHz band as a vertical stripe — see `sweep`. Change to match another
// strip; frequencies auto-adjust.
const COLS: usize = 10;
const ROWS: usize = 6;
const NUM_LEDS: usize = COLS * ROWS;

/// Chain index of matrix position (row, col), following the serpentine wiring.
fn led_index(r: usize, c: usize) -> usize {
    if r.is_multiple_of(2) {
        r * COLS + c
    } else {
        r * COLS + (COLS - 1 - c)
    }
}

// The whole sweep is logged as one line, so it must fit a single log line.
// Worst case per value: "-127" + ',' = 5 bytes; plus "RSSI [", ']' and CRLF.
const _: () = assert!(NUM_LEDS * 5 + 9 <= crate::LOG_LINE_CAP);

// Total duration of one RSSI sweep across all bands.
const RSSI_TOTAL_MS: u64 = 10;

// Right-shift applied to every RGB channel before sending to the strip — the
// brightness knob for the whole display. 2 = peak 63, 3 = peak 31, 4 = peak 15,
// 5 = peak 7, 6 = peak 3.
const BRIGHTNESS_SHIFT: u32 = 5;

// Per-band pause inside the RSSI sweep so the total sweep ≈ RSSI_TOTAL_MS.
// subtract ~70 µs for the actual sample_rssi() blocking time.
const RSSI_PAUSE_US: u64 = (RSSI_TOTAL_MS * 1000 / NUM_LEDS as u64).saturating_sub(70);

// WS2812 SPI frame: 12 bytes/pixel (4-bit encoding) + 13 reset bytes (104 µs
// low at 4 MHz ≥ the 50 µs WS2812 reset requirement).
const WS_BUF_SIZE: usize = NUM_LEDS * 12 + 13;

// ── Linear-power model + colour ───────────────────────────────────────────────
//
// RSSI is a logarithmic quantity (dBm); averaging or interpolating in dBm is
// wrong. We convert each reading to *linear power* (via a lookup table, since
// there is no libm in no_std), average and smooth in the linear domain, then
// spread the colour linearly across a chosen power range.
//
// RSSISAMPLE magnitude: RSSI dBm = −magnitude (larger magnitude = weaker).

// Colour-position anchors (magnitudes → dBm = −magnitude).
const STRONG_MAG: u8 = 50; // −50 dBm → full strength → Green
const WEAK_MAG: u8 = 82; //   −82 dBm → floor         → Red / off

// Linear-power lookup table, anchored at the weak end for resolution:
//   LIN[REF_MAG] = LIN_SCALE, and each 1 dB stronger multiplies by
//   10^(0.1) ≈ 10000/7943 (each 1 dB weaker multiplies by 7943/10000).
// Values below ~ −27 dBm overflow u32 and are never read (see `lin_power`).
const REF_MAG: usize = 100;
const LIN_SCALE: u32 = 256;

const fn build_lin_table() -> [u32; 128] {
    let mut t = [0u32; 128];
    t[REF_MAG] = LIN_SCALE;
    // Stronger (lower magnitude): ×10^(0.1) per dB.
    let mut m = REF_MAG;
    while m > 0 {
        t[m - 1] = ((t[m] as u64 * 10000) / 7943) as u32;
        m -= 1;
    }
    // Weaker (higher magnitude): ×10^(−0.1) per dB.
    let mut m = REF_MAG;
    while m < 127 {
        t[m + 1] = ((t[m] as u64 * 7943) / 10000) as u32;
        m += 1;
    }
    t
}

const LIN: [u32; 128] = build_lin_table();

// Clamp the low (very-strong) end to keep the lookup inside the u32-valid range;
// anything stronger than STRONG_MAG already saturates the colour to Green.
const LIN_MIN_MAG: u8 = 30;

const P_WEAK: u32 = LIN[WEAK_MAG as usize];
const P_STRONG: u32 = LIN[STRONG_MAG as usize];

// Relative linear power for an RSSI magnitude.
fn lin_power(mag: u8) -> u32 {
    LIN[mag.clamp(LIN_MIN_MAG, 127) as usize]
}

// Linear colour position for a linear power: 0 = weak (Red), 255 = strong (Green).
fn strength_t(p: u32) -> u8 {
    if p <= P_WEAK {
        return 0;
    }
    if p >= P_STRONG {
        return 255;
    }
    (((p - P_WEAK) as u64 * 255) / (P_STRONG - P_WEAK) as u64) as u8
}

// Discrete strength levels for the matrix: fixed hues, no blending, so
// neighbouring bands read as distinct cells instead of a smooth ribbon.
// Thresholds are dBm anchors on the smoothed linear power (magnitudes:
// RSSI dBm = −mag, so larger magnitude = weaker). Everything is dimmed by
// [`BRIGHTNESS_SHIFT`].
//
// Anchored to the 2026-08-26 bench sweeps: the noise floor sits at −102…−106,
// frequent small rises at −95…−100, moderate activity at −85…−95, and signal
// bursts span −65…−80 with peaks at −50…−64. The five levels spread across
// that range so the floor stays dark while every rise-to-burst gradient gets a
// distinct cell.
const LEVEL_OFF_MAG: u8 = 99; // below −99 dBm → LED off (the noise floor)
const LEVEL_RED_MAG: u8 = 91; // −99…−91  → red (rises above the floor)
const LEVEL_AMBER_MAG: u8 = 82; // −91…−82  → amber (moderate activity)
const LEVEL_GREEN_MAG: u8 = 68; // −82…−68  → green (bursts); ≥ −68 → white

fn level_color(p: u32) -> (u8, u8, u8) {
    let dim = |v: u8| v >> BRIGHTNESS_SHIFT;
    if p <= LIN[LEVEL_OFF_MAG as usize] {
        (0, 0, 0)
    } else if p <= LIN[LEVEL_RED_MAG as usize] {
        (dim(255), dim(45), dim(45))
    } else if p <= LIN[LEVEL_AMBER_MAG as usize] {
        (dim(255), dim(165), dim(30))
    } else if p <= LIN[LEVEL_GREEN_MAG as usize] {
        (dim(35), dim(255), dim(35))
    } else {
        (dim(255), dim(255), dim(255)) // the −50…−64 peaks stand out as white
    }
}

// Green(strong) → Blue(middle) → Red(weak). Full-scale (0..255) components.
//   t = 0   → Red     (255, 0,   0)
//   t = 128 → Blue    (0,   0,   255)
//   t = 255 → Green   (0,   255, 0)
fn strength_color(t: u8) -> (u8, u8, u8) {
    let lerp =
        |a: u8, b: u8, tt: u8| -> u8 { (a as i16 + (b as i16 - a as i16) * tt as i16 / 255) as u8 };
    const RED: (u8, u8, u8) = (255, 0, 0);
    const BLUE: (u8, u8, u8) = (0, 0, 255);
    const GREEN: (u8, u8, u8) = (0, 255, 0);
    if t < 128 {
        let tt = (t as u16 * 2).min(255) as u8; // Red → Blue
        (
            lerp(RED.0, BLUE.0, tt),
            lerp(RED.1, BLUE.1, tt),
            lerp(RED.2, BLUE.2, tt),
        )
    } else {
        let tt = ((t - 128) as u16 * 2).min(255) as u8; // Blue → Green
        (
            lerp(BLUE.0, GREEN.0, tt),
            lerp(BLUE.1, GREEN.1, tt),
            lerp(BLUE.2, GREEN.2, tt),
        )
    }
}

// ── Exponential-decay smoothing state ─────────────────────────────────────────
//
// Persists across sweeps so the strip and onboard LED lag/damp their changes.
// Scale-preserving EMA in the linear power domain: value = (prev + 3·current)/4.
// Single-task access (only `sweep`, from `rssi_task`), matching the `WS_BUF` idiom.
struct SmoothState {
    per_led: UnsafeCell<[u32; NUM_LEDS]>,
    avg: UnsafeCell<u32>,
}
unsafe impl Sync for SmoothState {}
static SMOOTH: ModeRef<SmoothState> = ModeRef::new();

// One EMA step: (prev + 3·current) / 4, computed in u64 to avoid overflow.
fn ema(prev: u32, current: u32) -> u32 {
    ((prev as u64 + 3 * current as u64) / 4) as u32
}

// ── Displayed-color crossfade state ───────────────────────────────────────────
//
// The discrete strength levels snap between hues when a smoothed value crosses
// a threshold — on a noisy floor that reads as rapid blinking. Each frame we
// blend every LED's *displayed* colour 25% toward its target, so level changes
// fade over ~4 frames instead of snapping.
struct DisplayState {
    colors: UnsafeCell<[[u8; 3]; NUM_LEDS]>,
}
unsafe impl Sync for DisplayState {}
static DISPLAY: ModeRef<DisplayState> = ModeRef::new();

/// Blend `a` toward `b` by `frac`/256.
fn lerp_u8(a: u8, b: u8, frac: u16) -> u8 {
    (a as u16 + ((b as u16 - a as u16) * frac) / 256) as u8
}

// ── Frequency mapping ─────────────────────────────────────────────────────────

// Returns the RADIO FREQUENCY offset (MHz above 2400) for LED / scan index i.
// i=0 → offset 2 (2402 MHz), i=NUM_LEDS−1 → offset 80 (2480 MHz).
fn led_freq(i: usize) -> u8 {
    (2 + i * 78 / (NUM_LEDS - 1)) as u8
}

// ── WS2812 encoding ───────────────────────────────────────────────────────────
//
// 4 MHz SPI (250 ns/bit): each WS2812 bit = 4 SPI bits.
//   '1' → 0b1110  (750 ns HIGH + 250 ns LOW)
//   '0' → 0b1000  (250 ns HIGH + 750 ns LOW)
// 8 LED bits × 4 SPI bits = 32 SPI bits = 4 bytes. One LED (GRB) = 12 bytes.
//
// Why 4 MHz and not 2 MHz: at 2 MHz the '0' pulse is 500 ns — exactly on the
// WS2812B 0-code boundary (350 ± 150 ns) — and clone LEDs misread it as a '1'.
// That bleaches the low bits of dimmed values (a dim value is mostly 0-bits,
// so it reads as full white: the "dim does nothing" symptom) and washes out
// the colour bands. 4 MHz puts both pulses comfortably inside spec.

// WS2812 SPI frame buffer (must be in RAM for EasyDMA).
static WS_BUF: ModeRef<SyncBuf<WS_BUF_SIZE>> = ModeRef::new();

/// RSSI-monitor-only state. Its LED history and EasyDMA frame do not coexist
/// with the other boot modes, so they live in the binary's mode arena.
pub struct Storage {
    smooth: SmoothState,
    display: DisplayState,
    ws_buf: SyncBuf<WS_BUF_SIZE>,
}

impl Storage {
    pub const fn new() -> Self {
        Self {
            smooth: SmoothState {
                per_led: UnsafeCell::new([0; NUM_LEDS]),
                avg: UnsafeCell::new(0),
            },
            display: DisplayState {
                colors: UnsafeCell::new([[0; 3]; NUM_LEDS]),
            },
            ws_buf: SyncBuf::new(),
        }
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}

/// # Safety
/// Must be called exactly once before RSSI mode starts.
pub unsafe fn bind_storage(storage: &'static Storage) {
    unsafe {
        SMOOTH.bind(&storage.smooth);
        DISPLAY.bind(&storage.display);
        WS_BUF.bind(&storage.ws_buf);
    }
}

fn encode_color_byte(byte: u8) -> [u8; 4] {
    let mut bits = 0u32;
    for i in 0..8 {
        bits <<= 4;
        bits |= if byte & (0x80 >> i) != 0 {
            0b1110
        } else {
            0b1000
        };
    }
    [
        (bits >> 24) as u8,
        (bits >> 16) as u8,
        (bits >> 8) as u8,
        bits as u8,
    ]
}

fn build_ws_frame(colors: &[(u8, u8, u8); NUM_LEDS]) {
    let buf = unsafe { &mut *WS_BUF.0.get() };
    let mut pos = 0;
    for &(r, g, b) in colors {
        buf[pos..pos + 4].copy_from_slice(&encode_color_byte(g));
        buf[pos + 4..pos + 8].copy_from_slice(&encode_color_byte(r));
        buf[pos + 8..pos + 12].copy_from_slice(&encode_color_byte(b));
        pos += 12;
    }
    for b in &mut buf[pos..] {
        *b = 0x00;
    } // reset pulse
}

// ── RSSI-only scan ────────────────────────────────────────────────────────────

// Tunes to `freq_offset`, ramps up receiver, takes one RSSI sample, disables.
// Blocking; ~70 µs. Returns RSSISAMPLE magnitude (RSSI dBm = −magnitude).
fn sample_rssi(freq_offset: u8) -> u8 {
    let r = pac::RADIO;
    ensure_disabled(); // guard against leftover radio state
    r.frequency().write(|w| {
        w.set_frequency(freq_offset);
        w.set_map(vals::Map::Default);
    });
    r.events_rxready().write_value(0);
    r.events_rssiend().write_value(0);
    r.events_disabled().write_value(0);
    r.tasks_rxen().write_value(1); // ramp up (~40 µs)
    while r.events_rxready().read() == 0 {}
    r.tasks_rssistart().write_value(1); // one sample (~8 µs)
    while r.events_rssiend().read() == 0 {}
    let magnitude = r.rssisample().read().rssisample();
    r.tasks_disable().write_value(1);
    let _ = crate::hal::radio::wait_disabled();
    r.events_disabled().write_value(0);
    magnitude
}

// ── RSSI spectrum sweep → WS2812 strip + raw-value log + onboard RGB ─────────
//
// Each reading is converted to linear power and smoothed with a scale-preserving
// EMA; the raw magnitudes are logged as one `RSSI [v0,…,vN]` line per sweep
// (dBm, index order = ascending frequency, see `led_freq`). The matrix renders
// the smoothed values as 10 band columns; the onboard RGB LED shows the band
// average; the noise-floor entropy stirs `rng`.
pub async fn sweep(spi: &mut Spim<'static>, rng: &mut Rng, leds: &mut impl crate::led::OnBoardLed) {
    let per = unsafe { &mut *SMOOTH.per_led.get() };
    let avg_state = unsafe { &mut *SMOOTH.avg.get() };

    let mut colors = [(0u8, 0u8, 0u8); NUM_LEDS];
    let displayed = unsafe { &mut *DISPLAY.colors.get() };
    let mut mags = [0u8; NUM_LEDS];
    let mut entropy: u32 = 0;
    let mut sum: u64 = 0; // Σ linear power this round (u64: 60 × up to ~2.6e9)
    for (i, p) in per.iter_mut().enumerate() {
        let mag = sample_rssi(led_freq(i));
        mags[i] = mag;
        let raw = lin_power(mag);
        sum += raw as u64;
        *p = ema(*p, raw); // linear-domain EMA
        // Column-major layout: matrix column c holds samples [6c..6c+6), so each
        // column is one ~7.8 MHz band rendered as a vertical stripe; the chain
        // index follows the serpentine wiring so the stripe stays upright.
        let (r, c) = (i % ROWS, i / ROWS);
        let target = level_color(*p);
        let cur = &mut displayed[led_index(r, c)];
        // 25% crossfade per frame — level snaps become smooth fades.
        cur[0] = lerp_u8(cur[0], target.0, 64);
        cur[1] = lerp_u8(cur[1], target.1, 64);
        cur[2] = lerp_u8(cur[2], target.2, 64);
        colors[led_index(r, c)] = (cur[0], cur[1], cur[2]);
        // Low bits of noise-floor RSSI carry real entropy — fold them in.
        entropy = entropy.wrapping_mul(31).wrapping_add(mag as u32);
        Timer::after_micros(RSSI_PAUSE_US).await;
    }
    rng.stir(entropy);

    // Average strength across all channels (linear domain), smoothed, → onboard
    // RGB. Dimmed by the same [`BRIGHTNESS_SHIFT`] as the strip.
    let avg_raw = (sum / NUM_LEDS as u64) as u32;
    *avg_state = ema(*avg_state, avg_raw);
    let (ar, ag, ab) = strength_color(strength_t(*avg_state));
    leds.set(crate::led::Rgb::new(
        ar >> BRIGHTNESS_SHIFT,
        ag >> BRIGHTNESS_SHIFT,
        ab >> BRIGHTNESS_SHIFT,
    ));

    build_ws_frame(&colors);
    let buf = unsafe { &*WS_BUF.0.get() };
    let _ = spi.write_from_ram(buf).await;

    // Raw per-point signal strength, one line per sweep.
    {
        use core::fmt::Write;
        let mut s = crate::LogLine::new();
        let _ = write!(s, "RSSI [");
        for (i, &m) in mags.iter().enumerate() {
            if i > 0 {
                let _ = write!(s, ",");
            }
            let _ = write!(s, "{}", -(m as i16));
        }
        let _ = write!(s, "]");
        crate::terminate_line(&mut s);
        log_send(s);
    }
}

// ── Mode ──────────────────────────────────────────────────────────────────────
//
// The RSSI-monitor boot mode: it captures no packets (no sink) and drives both the
// WS2812 strip and the onboard RGB LED **inside** [`sweep`], so it holds the SPI +
// PWM and `led_control` is a no-op. USB build only.

/// Holds the WS2812 SPI and the onboard PWM LED it drives from sweep data; `K` is
/// carried only for trait uniformity (this mode has no capture sink).
pub struct RssiMonitor<K: super::CaptureSink> {
    spi: Option<Spim<'static>>,
    leds: Option<Pwm>,
    _k: PhantomData<K>,
}

impl<K: super::CaptureSink> RssiMonitor<K> {
    pub fn new(spi: Spim<'static>, leds: Pwm) -> Self {
        Self {
            spi: Some(spi),
            leds: Some(leds),
            _k: PhantomData,
        }
    }
}

impl<K: super::CaptureSink> Mode for RssiMonitor<K> {
    type Sink = K;

    async fn init<F: core::future::Future<Output = ()>>(
        &mut self,
        _ctx: &'static Ctx<K>,
        setup: F,
    ) {
        setup.await;
    }

    async fn run(&mut self, ctx: &'static Ctx<K>) -> ! {
        let mut spi = self.spi.take().expect("run once");
        let mut leds = self.leds.take().expect("run once");
        loop {
            sweep(&mut spi, ctx.rng(), &mut leds).await;
        }
    }

    async fn led_control<L: OnBoardLed>(_led: &mut L) -> ! {
        // The onboard LED is driven inside the sweep in `run` — nothing separate.
        pending().await
    }
}
