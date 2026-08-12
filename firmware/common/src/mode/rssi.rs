//! RSSI spectrum sweep and its LED visualisation (RSSI-monitor boot mode).
//!
//! Each sweep samples RSSI across the 2.4 GHz band at `NUM_LEDS` evenly-spaced
//! points, converts each reading to linear power, smooths it, and colours the
//! WS2812 strip (per-channel) plus the onboard RGB LED (band average) on a
//! Green(strong)→Blue(mid)→Red(weak) scale. The raw magnitudes are also logged
//! — one `RSSI [v0,…,vN]` array per sweep — and noise-floor entropy is folded
//! into the shared jitter PRNG (see [`crate::Rng`]).

use core::cell::UnsafeCell;
use core::future::pending;
use core::marker::PhantomData;

use embassy_nrf::pac;
use embassy_nrf::pac::radio::vals;
use embassy_nrf::spim::Spim;
use embassy_time::Timer;

use super::{Ctx, Mode};
use crate::hal::radio::ensure_disabled;
use crate::led::{OnBoardLed, Pwm};
use crate::{log_send, Rng, SyncBuf};

// ── Strip configuration ───────────────────────────────────────────────────────

// Number of LEDs = number of RSSI scan points. Each point is evenly distributed
// across 2402–2480 MHz. Change this to match your strip; frequencies auto-adjust.
const NUM_LEDS: usize = 64;

// The whole sweep is logged as one line, so it must fit a single log line.
// Worst case per value: "-127" + ',' = 5 bytes; plus "RSSI [", ']' and CRLF.
const _: () = assert!(NUM_LEDS * 5 + 9 <= crate::LOG_LINE_CAP);

// Total duration of one RSSI sweep across all bands.
const RSSI_TOTAL_MS: u64 = 10;

// Per-band pause inside the RSSI sweep so the total sweep ≈ RSSI_TOTAL_MS.
// subtract ~70 µs for the actual sample_rssi() blocking time.
const RSSI_PAUSE_US: u64 = (RSSI_TOTAL_MS * 1000 / NUM_LEDS as u64).saturating_sub(70);

// WS2812 SPI frame: NUM_LEDS pixels × 9 bytes/pixel + 13 reset bytes.
const WS_BUF_SIZE: usize = NUM_LEDS * 9 + 13;

// ── Linear-power model + colour ───────────────────────────────────────────────
//
// RSSI is a logarithmic quantity (dBm); averaging or interpolating in dBm is
// wrong. We convert each reading to *linear power* (via a lookup table, since
// there is no libm in no_std), average and smooth in the linear domain, then
// spread the colour linearly across a chosen power range.
//
// RSSISAMPLE magnitude: RSSI dBm = −magnitude (larger magnitude = weaker).
//
// Colour scheme (position spread linearly over the power range):
//   strong → Green,  middle → Blue,  weak → Red.
// Hue carries strength at a fixed brightness so mid-strength (blue) stays clearly
// visible; a strip point below the weak floor is turned off to limit current.

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

// Green(strong) → Blue(middle) → Red(weak). Full-scale (0..255) components.
//   t = 0   → Red     (255, 0,   0)
//   t = 128 → Blue    (0,   0,   255)
//   t = 255 → Green   (0,   255, 0)
fn strength_color(t: u8) -> (u8, u8, u8) {
    let lerp = |a: u8, b: u8, tt: u8| -> u8 {
        (a as i16 + (b as i16 - a as i16) * tt as i16 / 255) as u8
    };
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
static SMOOTH: SmoothState = SmoothState {
    per_led: UnsafeCell::new([0; NUM_LEDS]),
    avg: UnsafeCell::new(0),
};

// One EMA step: (prev + 3·current) / 4, computed in u64 to avoid overflow.
fn ema(prev: u32, current: u32) -> u32 {
    ((prev as u64 + 3 * current as u64) / 4) as u32
}

// ── Frequency mapping ─────────────────────────────────────────────────────────

// Returns the RADIO FREQUENCY offset (MHz above 2400) for LED / scan index i.
// i=0 → offset 2 (2402 MHz), i=NUM_LEDS−1 → offset 80 (2480 MHz).
fn led_freq(i: usize) -> u8 {
    (2 + i * 78 / (NUM_LEDS - 1)) as u8
}

// ── WS2812 encoding ───────────────────────────────────────────────────────────
//
// 2 MHz SPI (500 ns/bit): each WS2812 bit = 3 SPI bits.
//   '1' → 0b110  (1000 ns HIGH + 500 ns LOW)
//   '0' → 0b100  ( 500 ns HIGH + 1000 ns LOW)
// 8 LED bits × 3 SPI bits = 24 SPI bits = 3 bytes. One LED (GRB) = 9 bytes.

// WS2812 SPI frame buffer (must be in RAM for EasyDMA).
static WS_BUF: SyncBuf<WS_BUF_SIZE> = SyncBuf::new();

fn encode_color_byte(byte: u8) -> [u8; 3] {
    let mut bits = 0u32;
    for i in 0..8 {
        bits <<= 3;
        bits |= if byte & (0x80 >> i) != 0 {
            0b110
        } else {
            0b100
        };
    }
    [(bits >> 16) as u8, (bits >> 8) as u8, bits as u8]
}

fn build_ws_frame(colors: &[(u8, u8, u8); NUM_LEDS]) {
    let buf = unsafe { &mut *WS_BUF.0.get() };
    let mut pos = 0;
    for &(r, g, b) in colors {
        buf[pos..pos + 3].copy_from_slice(&encode_color_byte(g));
        buf[pos + 3..pos + 6].copy_from_slice(&encode_color_byte(r));
        buf[pos + 6..pos + 9].copy_from_slice(&encode_color_byte(b));
        pos += 9;
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

// ── RSSI spectrum sweep → WS2812 strip + onboard RGB ──────────────────────────
//
// NUM_LEDS × ~70 µs ≈ 4.5 ms scan + ~1.5 ms strip write ≈ 6 ms/cycle. Each
// reading is converted to linear power, smoothed with a scale-preserving EMA,
// and coloured Green(strong)→Blue(mid)→Red(weak). The onboard RGB LED (via PWM)
// shows the (also-smoothed) average across all channels. Raw magnitudes are
// logged as one `RSSI [v0,…,vN]` array per sweep (dBm, index order = ascending
// frequency, see `led_freq`) and their low bits stir `rng`.
pub async fn sweep(spi: &mut Spim<'static>, rng: &mut Rng, leds: &mut impl crate::led::OnBoardLed) {
    let per = unsafe { &mut *SMOOTH.per_led.get() };
    let avg_state = unsafe { &mut *SMOOTH.avg.get() };

    let mut colors = [(0u8, 0u8, 0u8); NUM_LEDS];
    let mut mags = [0u8; NUM_LEDS];
    let mut entropy: u32 = 0;
    let mut sum: u64 = 0; // Σ linear power this round (u64: 64 × up to ~2.6e9)
    for i in 0..NUM_LEDS {
        let mag = sample_rssi(led_freq(i));
        mags[i] = mag;
        let raw = lin_power(mag);
        sum += raw as u64;
        per[i] = ema(per[i], raw); // linear-domain EMA
        colors[i] = if per[i] <= P_WEAK {
            (0, 0, 0) // below the weak floor → strip point off (saves current)
        } else {
            let (r, g, b) = strength_color(strength_t(per[i]));
            (r >> 2, g >> 2, b >> 2) // strip peak ~64 to limit current draw
        };
        // Low bits of noise-floor RSSI carry real entropy — fold them in.
        entropy = entropy.wrapping_mul(31).wrapping_add(mag as u32);
        Timer::after_micros(RSSI_PAUSE_US).await;
    }
    rng.stir(entropy);

    // Average strength across all channels (linear domain), smoothed, → onboard RGB.
    let avg_raw = (sum / NUM_LEDS as u64) as u32;
    *avg_state = ema(*avg_state, avg_raw);
    let (ar, ag, ab) = strength_color(strength_t(*avg_state));
    leds.set(crate::led::Rgb::new(ar, ag, ab));
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
    build_ws_frame(&colors);
    let buf = unsafe { &*WS_BUF.0.get() };
    let _ = spi.write_from_ram(buf).await;
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
        Self { spi: Some(spi), leds: Some(leds), _k: PhantomData }
    }
}

impl<K: super::CaptureSink> Mode for RssiMonitor<K> {
    type Sink = K;

    async fn init<F: core::future::Future<Output = ()>>(&mut self, _ctx: &'static Ctx<K>, setup: F) {
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
