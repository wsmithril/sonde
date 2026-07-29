# Sonde — design notes

Internals and the reasoning behind them: what the firmware does at the register
and task level, and the measurements that fixed each choice. The
[README](../README.md) describes Sonde from the outside — what it captures and
how to run it. This document is for changing it.

Every measurement below is from hardware, on a Seeed XIAO nRF52840, dated where
it matters. Radio references are to the nRF52840 Product Specification v1.11.
The **headless** build (§1) targets a different board — a nice!nano v2 clone —
but the same nRF52840, so the radio/timing measurements carry over unchanged;
only the board-level plumbing (pins, LED) differs.

---

## 1. Platform

nRF52840 on the XIAO, Adafruit UF2 bootloader. App flash starts at `0x27000`
and app RAM at `0x20006000`; the low 24 KB of RAM belongs to the
SoftDevice/bootloader region. The SoftDevice is present in flash but never
enabled — Sonde drives the RADIO peripheral directly. Because no SoftDevice is
running, `embassy_nrf::nvmc::Nvmc` writes go straight to flash with no
SD flash-API calls.

Target `thumbv7em-none-eabi` (soft float). Rust edition 2024. `.cargo/config.toml`
at the workspace root sets `[build] target`, so the binaries land under
`target/thumbv7em-none-eabi/release/` at the workspace root, not `firmware/`.

**Two builds, two boards.** The workspace is a shared library plus two binary
crates, so the same capture/decode code produces two firmwares for two different
boards:

- **`sonde-usb`** (`firmware/usb`) → **Seeed XIAO nRF52840**. The status-quo build:
  decoded ASCII console over USB CDC, QSPI name tables, provisioning, the RGB LED.
- **`sonde-headless`** (`firmware/headless`) → **nice!nano v2 clone**. Battery
  capture to an SD card as PCAP/text with a read-only FAT32 view over USB-MSC; no
  console, no QSPI, no deep decode (dead-code-eliminated), a single mono LED.

`sonde-headless` is designed as a **drop-and-collect** probe: left running on a
battery in a space, retrieved and read back later. That reframes the trade-offs
toward **cheap but still capable** — the goal is to be able to scatter several. So
it targets a ~$5 nice!nano v2 clone instead of the XIAO, drops the QSPI name
tables (decode moves to the host, off the raw capture), stores to a commodity SD
card, and indicates on one LED. Nothing on the capture path is cut: it is the same
nRF52840 running the same radio code from `firmware/common`. The cost of "cheap"
is paid in board-level unknowns (clone pin-out, LED, regulator) — hence the CONFIRM
markers — not in capture capability.

Both are the same nRF52840 with the Adafruit UF2 bootloader, so `memory.x` (app at
`0x27000`) and the reset-cycled boot mode are shared. What differs is board-level:
the nice!nano has a single LED (P0.15, not the XIAO's RGB trio), no onboard QSPI
flash, and a different pin-out — the headless pin constants are marked CONFIRM
against the specific clone. `firmware/common` is board-agnostic; the capture modes
drive an `impl led::Sink`/`ChanSink` rather than a concrete LED, so each binary
supplies its own backend (`usb/src/led.rs` RGB, `headless/src/led.rs` mono).

Build and lint (`cargo build --release` builds both via `default-members`):

```sh
cargo build --release
cargo clippy --release -p sonde-usb -p sonde-headless  # no --all-targets: no_std has no `test`
rust-size target/thumbv7em-none-eabi/release/sonde-usb
```

Flash occupancy: 276,956 / 811,008 B = 34.1% (`.vector_table + .text + .rodata
+ .data`). RAM 125,260 / 237,568 B = 52.7%, of which the 192-entry USB `LOG`
channel is 101 KB — everything else in `.bss` together is under 24 KB. The 91.4%
flash figure recorded here previously predated the QSPI asset offload, when the
486 KB of vendor tables still lived in internal flash.

`AtomicU64` does not exist on this target. Shared mutable state uses the
`UnsafeCell` + `unsafe impl Sync` idiom (`SEEN`, `STATS`, `SyncBuf`,
`LOG_STAMP`), which is sound here because the Embassy thread-mode executor is
cooperative and single-threaded: a task holds the CPU until it `.await`s. The
corollary any reader has to respect: a `snapshot`-style accessor returns by
value, so no borrow of shared state is ever held across an `.await`.

### LED indication (`common/src/led.rs` + per-board backend)

The LED is board hardware, so the split lands on a seam: `common/src/led.rs` holds
the board-agnostic model — `Rgb`/colours, the `led::LED` command signal for GATT,
and two sink traits, `Sink` (`set`) and `ChanSink: Sink` (`set_chan`). The capture
modes drive an `impl Sink`/`ChanSink`, never a concrete LED, so each board supplies
its own backend and a mode that indicates elsewhere passes `led::Noop`.

#### USB build (XIAO) — RGB, `usb/src/led.rs`

One common-anode RGB LED on P0.26 (R), P0.30 (G) and P0.06 (B), every channel
**active-LOW**. All five modes use those three pins for something different, so
the pin map, the polarity and the duty convention live in one module rather than
being re-derived per mode — which is how three subtly different copies of the
same comment came to exist before it.

Two backends, because the modes do not want the same thing:

- **`led::Pwm`** — three PWM channels, 8 bits per channel, any mix. Each update is
  one fire-and-forget DMA kick: `Pwm::set` reloads the sequence and starts the DMA
  by hand via raw `pac`, deliberately *not* calling `SimplePwm::set_all_duties`,
  whose trailing `EVENTS_SEQEND` busy-wait costs a full PWM period. That wait only
  guards against a second update overwriting the DMA source mid-transfer, and every
  caller spaces its updates ≥1 ms apart while the transfer finishes in ≤64 µs, so
  dropping it is safe and keeps the executor free for the radio (§4). The period —
  `Prescaler::Div1` over a 1024 countertop, 15.6 kHz — now sets only how soon a new
  duty takes effect (≤64 µs, the next period boundary), not any CPU cost. The
  carrier frequency itself is irrelevant: anything above a few hundred hertz is
  invisible.
- **`led::Gpio`** — three plain outputs, the eight corners of the cube, one
  register write per channel and no DMA. The fit for the boot-mode indicator (which
  runs before the executor exists) and for connection-follow (which toggles the LED
  between radio events, where a DMA-backed update is more than the loop wants).

`DutyCycle::normal(v)` drives the pin high once the counter reaches `v`, so with
active-LOW LEDs the lit fraction is `v/max_duty` — the duty value *is* the
brightness, not its complement. `Pwm::set` squares the channel value on the way
through, because perceived brightness goes roughly as duty²; without it a
two-colour fade reads as washed-out white across its whole middle. Crossfades
(`Rgb::mix`) interpolate before the gamma, so the curve is applied once.

`led::indicator` is the task behind the `led::LED` signal — solid colours,
single-channel changes that compose onto whatever is displayed, and blink
patterns of `(colour, count, on_ms, off_ms, settle colour)`. A new command
pre-empts a blink in flight, so a pattern can never delay a state change; the
`blink` helpers return the pattern's duration for callers that want the flashes
to actually be seen. GATT-central mode is its user. Sniff mode runs `led::sniff`
on the same hardware instead (§5), and connection-follow owns a `led::Gpio`
directly, so at most one of the three is ever spawned.

#### Headless build (nice!nano v2) — mono, `headless/src/led.rs`

The nice!nano has a single LED (P0.15, **active-LOW** — both the pin and polarity
marked CONFIRM against the clone), so the per-mode colour vocabulary does not
apply. The scheme collapses to two signals on one LED: at boot it blinks the
boot-mode ordinal (`boot::mode_index(mode) + 1` flashes) so the active mode is
still legible, then a **1 ms flash per captured packet in every mode**. The flash
is decoupled from the mode code — the capture-queue consumers call `led::flash()`
as they drain packets, and connection-follow is handed `led::Noop` — so it needs
none of the RGB machinery above. One task owns the pin for the whole run; a
coalescing one-slot signal means a burst of packets is one pending flash, not a
backlog. The no-card fatal path blinks the same LED (`led::fatal_blink`).

### Boot-mode persistence

The reset-cycled boot mode lives in a reserved 4 KB flash page at `0xEC000`.
`memory.x` ends the app FLASH region there (`LENGTH = 0xEC000 - 0x27000`), so
the page sits outside everything `objcopy -O binary` + DFU writes and survives
reflashing.

`next_boot_mode(p.NVMC)` append-logs one 4-byte word per boot: scan 1024 slots
for the last valid entry and the first free one, compute `(prev + 1) % N`, write
`SLOT_TAG(0x0DE00000) | mode` into the free slot. No erase on the common path —
the page is erased about once per 1024 reboots, or immediately when the contents
are unrecognised (stale bytes from an older build, or a torn write). Needs
`embedded-storage = "0.3"`.

**Flash is the only place this survives.** The bootloader runs on *every* reset
and clobbers both candidates in RAM:

- `POWER.GPREGRET` / `GPREGRET2` are not preserved.
- The top of RAM is not preserved either. The bootloader sets its stack pointer
  to `0x20040000` and grows down through that region on its first call, and it
  parks its double-tap magic at `0x2003FFFC`. A cell pinned at `0x2003FFE0` read
  back cold on every boot — mode stuck at 0 forever. Carving the top of RAM out
  of the linker script protects the cell from cortex-m-rt and from our own
  stack, but not from the bootloader, which owns that memory first.

Consequence of using flash: **every reset advances the mode**, including a cold
power-on, because flash cannot distinguish power-on from pin reset without
consulting `RESETREAS`.

### Crash reporting (`panic.rs`)

A panic used to be indistinguishable from a wedged radio, which cost real time:
`panic_probe` reports through RTT, which nothing reads without a debugger, and
then executes `udf` — HardFault, and cortex-m-rt's default handler is an
infinite loop. The capture just stops, exactly as it did for the `follow_aux`
busy-wait (§4), with nothing to tell the two apart.

The handler in `panic.rs` replaces it. It records `file:line` plus the truncated
panic message to a second reserved page at `0xED000` — 128-byte records,
appended by the same scheme as the boot-mode page — then halts on a blinking red
LED. `HardFault` is recorded the same way, with the faulting PC from the stacked
exception frame in place of the line number (resolve it with `addr2line`).
`report_and_clear()` prints anything found at the next boot and wipes the page,
so a report means "crashed since you last looked"; the history lives in the
capture files.

It deliberately does **not** self-reset. A reset lands in the *next* boot mode,
so a sniff capture would silently resume as an RSSI sweep.

Everything in the handler is written not to fault a second time: the message is
formatted through a truncating `fmt::Write` sink, the NVMC ready-waits are
bounded, and reads at boot go through memory-mapped flash so no `Peri` handle is
needed.

---

## 2. Clocks

```rust
config.hfclk_source = HfclkSource::ExternalXtal;
config.lfclk_source = LfclkSource::Synthesized;
```

LFCLK is `embassy-time`'s entire tick base, so it sets every connection anchor,
T_IFS deadline and hop instant in `gatt.rs` and `conn_follow.rs`.
`embassy_nrf::config::Config::default()` selects `LfclkSource::InternalRC`, and
on this board the internal RC measured **~3100 ppm slow** (2026-07-29) against a
500 ppm BLE budget: a locked follower re-anchoring on the master's own packet
every event showed a persistent `dM = −122 µs` on a 30 ms interval — 29907 of
"our" microseconds per 30000 real ones, ≈32666 Hz instead of 32768. The same
figure appeared against two different masters, and every `dM` was a whole
multiple of 30.5 µs (one tick), which is what identified the tick as the quantum.

**The symptom is correct packets on a wrong schedule.** Bit timing, whitening
and CRC all come off HFCLK and were always fine; only *when* Sonde listened or
transmitted was wrong. A link works for an event or two and then goes deaf: the
GATT central got `addr=1 crcok=1` (~97 µs late per 31.25 ms event, cumulative,
out of the peripheral's window within ~10 events) and the follower needed
constant re-hunts.

`Synthesized` divides HFCLK, which is already sourced from the external crystal,
so it inherits HFXO accuracy and always starts (~100 µs). `ExternalXtal` is the
wrong choice here: `embassy_nrf::init` spins unbounded on `EVENTS_LFCLKSTARTED`,
so a board with no 32.768 kHz crystal populated hangs at boot, recoverable only
by double-tap-reset into the bootloader. The cost of `Synthesized` — HFCLK must
keep running — is irrelevant on USB power with the radio on continuously.

Confirmed fixed 2026-07-29: the GATT central completes full enumeration,
`ev=48 addr=43 crcok=43` and `ev=81 addr=43 crcok=43` against two Macs. The
decisive column is `gap`: 213–427 µs (real T_IFS plus the peer's air time)
where it had been a flat 1525 µs miss timeout.

**Connection intervals must be a whole number of ticks.** `Duration::from_micros`
truncates: 45000 µs → 1474 ticks = 44982.9 µs, 17 µs early per event (380 ppm).
`gatt.rs` uses 25 × 1.25 ms = 31.25 ms = exactly 1024 ticks at 32768 Hz, guarded
by `const _: () = assert!(...)`. This is an order of magnitude smaller than the
LFCLK error above and was fixed separately.

---

## 3. Concurrency and the log path

The Embassy thread-mode executor runs the mode task alongside the USB device
task, the CDC drain task, the LED indicator task, and — in BLE-sniff mode — the
decode task.

`LOG` is a 192-deep `Channel<CriticalSectionRawMutex, (Instant, LogLine), 192>`
of 512-byte lines. `log_send` uses `try_send().ok()`, so a radio deadline is
never missed waiting on USB; lines are dropped rather than delayed.

Depth matters twice over. At the original depth of 8, `decode_ext_adv`'s 6–9
`emit()` fan-out dropped the `AUX_ADV_IND … crc=ok` label — emitted after the
decode — 100% of the time. Labels are now emitted *before* the decode that
follows them, mirroring the primary path, so the label count equals the
decoded-block count.

Depth 32 was still not enough: every sniff capture lost ~10% of its lines
(10,353 of 109,279 in one 43 s run, 39,941 in a 204 s run). Nothing in the
`stats:` line says so — its `dropped=` is the *decode* queue. Log-queue loss is
reported only by the `*** N log lines dropped (queue full)` notices, which are
written straight to the endpoint because the channel a queued notice would sit
in is the one that just overflowed. Count those, not `dropped=`, when asking
whether a capture is complete.

### Log lines are packed into full CDC packets

The drain task used to write a packet per timestamp and a packet per body. A
line averages 65 bytes, so that was two *short* bulk transfers per line —
~4600 a second under sniff load — and a short packet ends its transfer, so
each one paid a full round trip. Lines are now appended into a 64-byte staging
buffer and shipped only when it fills, which halves the transfer count and
makes all but the last full-size. The remainder is flushed whenever the channel
runs dry, so a quiet link still delivers its last line immediately rather than
holding it until some later line fills the packet; staging restarts empty on
reconnect, so half a line is never spliced onto a new stream.

Packing raises sustained throughput; depth absorbs bursts. Both are needed — the
drain task is not slow on average, it just is not scheduled at all while a
crowded channel visit is fanning out.

### Timestamps are taken at queue time

Every line carries the instant it was queued, so a slow USB drain cannot
masquerade as an event-timing anomaly. In BLE-sniff mode decoding happens in a
different task than capture, which would otherwise stamp lines at decode time
and reintroduce exactly that artifact. One override in `main.rs` fixes it for
the whole decoder without threading an `Instant` through 45 vendor decoders:

```rust
static LOG_STAMP: StampCell = StampCell(UnsafeCell::new(None));

pub(crate) fn log_send(s: LogLine) {
    let t = unsafe { *LOG_STAMP.0.get() }.unwrap_or_else(Instant::now);
    LOG.try_send((t, s)).ok();
}

/// Stamp every line `f` emits with `t`.
pub(crate) fn with_log_stamp(t: Instant, f: impl FnOnce()) { … }
```

`f` is a plain `FnOnce`, so no `.await` can interleave another task's logging
between set and clear. The cell holds `None` outside the guard, which leaves
`rssi`, `gatt` and `conn_follow` on `Instant::now()`. The decoder holds no
mutable state — no `static mut`, `UnsafeCell`, `Cell` or atomic anywhere under
`decoder/` — so driving it from a second task is safe.

### Every line is scrubbed of control characters before it is queued

Log lines quote text taken off the air — device names, URIs, ATT string values —
and a name is an arbitrary byte string chosen by the advertiser. A capture that
ran for 43 s ended mid-scan with no error, no `dropped=` count and no visible
cause; the firmware was still running. The names in that log carried raw
`0x00`, `0x08`, `0x0C`, `0x15`, `0x16`, `0x1A` and `0x1D`, so a name containing
`0x13` (DC3/XOFF) was only a matter of time: the host tty's `IXON` line
discipline consumes it as flow control, and because it is consumed the byte
never reaches `tio` to appear in the file. The log simply stops.

`log_send` replaces every C0 control, `0x7F`, and the two-byte UTF-8 encodings
of the C1 controls (`0xC2 0x80..0x9F`, which include CSI) with `.`, leaving the
trailing CRLF. CR and LF inside the body are scrubbed too — a newline in a name
would split one record into two, and the second would carry no timestamp. It is
done at the sink rather than at each of the ~20 decoders that quote text, so a
new decoder cannot reintroduce it.

### Diagnostics inside a synchronous loop are a USB deadline

A blocking diagnostic with no `await` between iterations is one unbroken stretch
of unserviced CDC. `scan_probe`'s sweep at 4 configs × 3 s = 12 s passed the
host's control-transfer timeout. Keep any per-config cap under a second and put
a `Timer::after` between rows.

---

## 4. Radio rules that apply across modes

`common::radio_configure_ble` holds the shared setup — BLE PHY, whitening, CRC,
channel maths — for sniff, rssi, gatt and conn_follow. `radio_configure_154`
alongside it does the same for the 802.15.4 mode (§9); the two are mutually
exclusive and the rules below are the BLE ones unless said otherwise.

### The radio comes first — never block it

Every mode obeys one rule: **nothing may stall the radio, and the receiver should
be armed as close to all the time as the mode allows.** On a single-priority
cooperative executor this has a precise meaning — the CPU *is* the radio's
scheduler, so any task that holds the CPU without yielding delays whatever the
radio needs next: re-arming RX after an `EVENTS_END`, opening an aux window at its
captured deadline (§5), or driving a software turnaround (§7).

Blocking the CPU is not itself the sin — blocking the *radio* is. A busy-wait is
acceptable exactly when it cannot become a missed radio deadline:

- **Hardware carries the real-time edge.** T_IFS turnarounds and RX re-arm run off
  RADIO SHORTS and PPI (below, §7), so they hit their deadline whether or not the
  CPU is spinning. The GATT survey dwell (§7) *must* tight-poll with no
  `yield_now` — reacting to `EVENTS_END` within T_IFS beats handing the executor to
  the USB logger — and that CPU block is correct precisely because it is shorter
  than, and in service of, the radio's own schedule.
- **The wait is bounded and short.** `wait_disabled` caps its spin at ~15 ms
  against a ~6 µs ramp-down (below); an *unbounded* `while events_x == 0 {}` is not
  a stall but the end of the program — the task never yields again, so the radio
  work behind it never runs. Two captures died this way.
- **The block is off the radio's task.** Work on a timer-driven side task (the LED,
  stats) must stay short enough that the owning radio task's next poll is not pushed
  past its deadline. The LED PWM update is fire-and-forget for this reason (§1): a
  64 µs busy-wait on the sniff indicator task delayed the scan loop's re-arm by that
  much on every blink.

Everything not on the real-time edge yields: the sniff scan loop yields every
`PRIMARY_POLL_US` so USB drains while the radio listens (§5), decode runs in a
separate task so the receiver re-arms immediately (§5), and no shared-state borrow
is held across an `.await` (§1). Judge a mode by how much of the wall clock the
radio is actually listening, not by how much the CPU is idle.

### Ramp-up: `Fast` for RX-only, `Default` for T_IFS turnarounds

`MODECNF0.RU` selects a 40 µs (`Fast`) or 140 µs (`Default`) ramp. The split is
by whether a hardware counter is timed against the ramp.

**Hardware T_IFS is qualified only with `Default` ramp-up** (PS v1.11). TIFS is
timed from the last bit on air to just after READY, so `Fast` shifts the
turnaround by the ramp difference with nothing compensating. Every turnaround
had been on `Fast` and all three failed together: `conn_event` `addr=0` on 40/40
events, `scan_probe` 1 reply in 12, `conn_follow` never catching the
peripheral's reply. The `TURNAROUNDS` sweep in `scan_probe`, aggregated over 27
sweeps against 27 peers, settled it (2026-07-29):

| config | hits / attempts |
|---|---|
| `dflt/150` | 8 / 11 |
| `fast/110` | 7 / 26 |
| `fast/150` | 4 / 22 |
| `fast/190` | 1 / 19 |

`Ru::Default` is therefore set in `try_connect`, `configure_conn_radio` and
`conn_follow::configure_radio`. Use `.modify` rather than `.write` on `modecnf0`
so `DTX` is preserved.

`ble_sniff` is receive-only: every reception begins at `TASKS_RXEN` and starts
sampling at READY through the `RXREADY_START` short, so the ramp's only effect
is how soon READY arrives. `ble_sniff::use_fast_ramp_up()` sets `Fast` once per
boot, and `MODECNF0` holds that value across the `MODE`/`PCNF0` writes
`follow_aux` makes for a 2M- or Coded-PHY aux. Confirmed 2026-07-31:
ms-per-visit 1.92 → 1.82 (exactly the 100 µs, at both median and p10), capture
rate 522 → 550 pkt/s. The `dflt/150` row above predicts the same effect from the
other direction — it collects fewer `advs` per sweep precisely because the
140 µs ramp misses adverts while re-arming. That depresses its sample size, not
its hit rate, so compare turnaround configs on rate.

### `PCNF1.MAXLEN` bounds EasyDMA, not your buffer length

`radio_configure_ble` sets `MAXLEN = 255` deliberately, because a large
`AUX_ADV_IND` payload must survive aux following. Any module reusing it with a
smaller buffer must narrow `MAXLEN` to match: `gatt.rs` has a 64-byte `RX_BUF`
and `configure_conn_radio` now does
`r.pcnf1().modify(|w| w.set_maxlen(CONN_MAX_PAYLOAD as u8))` (62), plus a
`buf[1].min(...)` clamp so the payload slice cannot panic regardless of
configuration. A length byte corrupted on air would otherwise have the RADIO
write past `RX_BUF` into whatever follows in `.bss`. `ble_sniff.rs` and
`conn_follow.rs` use 258-byte buffers and are safe at `MAXLEN = 255`.

### `EVENTS_CRCOK`, not `EVENTS_END`, means "a good packet arrived"

`END` fires at the end of any reception whose ADDRESS matched, and the 4-byte
access address is robust enough that a payload mangled by interference still
ends normally. Anything that advances protocol state must gate on `CRCOK`.

`gatt.rs::conn_event` returned `Some(pdu)` on END alone and only *counted*
`CRCOK` for stats, so a corrupt packet reached `update_flow`, which advanced
SN/NESN off a garbage header: Sonde acks data it never received, the peer drops
it, and the ATT response is lost for good. The visible symptom was one log line
— `peer L2CAP frame too large (3590 B) — dropped`, 3590 = 0x0E06 — but the
damage was the flow-control desync. `conn_event` now does
`if !crc_seen { return None; }`, treating it exactly like silence so the
transaction retransmits. The gate is free on a healthy link, where captures show
`addr == crcok` (e.g. `ev=48 addr=43 crcok=43`).

### `PACKETPTR` is latched at each START

Writing it after a START safely redirects only the *next* transfer. The connect
turnaround exploits this by swapping speculatively on `EVENTS_ADDRESS`.

### Disabling the radio: clear SHORTS, clear the event, *then* trigger the task

All three steps are load-bearing, and `common.rs` is the only place that gets to
do them. `radio_ensure_disabled` (loud — a running radio is a bug here) and
`radio_disable_silent` (quiet — a running radio is expected) both route through
one `radio_force_disable`.

- **SHORTS first.** `disabled_txen`/`disabled_rxen` re-trigger the radio the
  instant it reaches DISABLED, so it never settles. `end_start` — which the
  primary scan leaves armed — re-arms the receiver underneath the ramp-down when
  an END lands during it.
- **Clear `EVENTS_DISABLED` before writing `TASKS_DISABLE`.** The reverse order
  loses the event outright whenever the radio reaches DISABLED between the two
  register writes, and the wait that follows then has nothing left to observe.
- **Bound the wait** (`wait_disabled`, 100_000 volatile reads ≈ 15 ms against a
  ramp-down capped at ~6 µs). On a single-priority cooperative executor an
  unbounded `while events_disabled == 0 {}` is not a stall, it is the end of the
  program: the task never yields again, so the USB drain task never runs and the
  capture stops mid-line with nothing to say why. Two 20-minute captures ended
  exactly that way, both on the first hop of an aux chase.

A timeout logs `radio_disable_timeout` and returns; the caller reconfigures and
starts as usual. Power-cycling the peripheral instead would reset MODE, PCNF, the
access address, CRC and TIFS — none of which the per-operation setup rewrites —
so the escape from a hypothetical hang would be certain deafness.

---

## 5. BLE sniff (`ble_sniff.rs`)

Passive. Dwells on 37/38/39 (LE 1M), decoding every PDU, and follows `AuxPtr`
chains onto the secondary channels.

### Scan loop

| constant | value | role |
|---|---|---|
| `ADV_TOTAL_MS` | 120 | three channels of `ADV_DWELL_MS` = 40 ms each |
| `ADV_DWELL_JITTER_MS` | 20 | random 0–20 ms added per channel |
| `PRIMARY_POLL_US` | 150 | `EVENTS_END` poll granularity |
| `RX_BUF` | `SyncBuf<258>` | 2-byte PDU header + 255-byte payload |

Dwell is jittered and the visit order reshuffled every cycle. A fixed cadence
aliases against an advertiser's fixed interval, and that failure mode is silent:
you land in the gaps forever and conclude the device is not there.

The dwell is a safety net for a dead channel, not a throughput parameter. The
loop breaks on `EVENTS_END`, and a live environment delivers a packet in a
median 1.8–2.2 ms against a 40–60 ms window. Across 41,820 visits: zero
timeouts. Across 942,960 visits in a quieter capture: 1,183 timeouts = 0.125% of
visits, ~1.6% of wall clock. Tuning it changes nothing measurable.

`PRIMARY_POLL_US = 150` is what makes short-offset aux packets reachable — an
`ADV_EXT_IND` is noticed within ~150 µs of airing, and its aux can follow only
~300 µs later (T_MAFS). Each poll yields to the executor, so USB keeps draining.

### Decode queue

Decoding and formatting a packet costs ~0.6 ms — about 100 µs per formatted line
at ~5.8 lines per packet (`core::fmt` + `heapless` on a 64 MHz M4), of which the
QSPI vendor lookup alone is ~0.3 ms. In a busy environment that was 14.8% of
wall clock spent with the receiver off.

The scan loop therefore copies each packet into an 8-deep
`Channel<CriticalSectionRawMutex, RxPacket, 8>` and re-arms immediately;
`log_task` drains it and decodes while the radio is listening again. `RxPacket`
is 288 B with alignment × 8 ≈ 2.4 KB of `.bss`, about 1% of RAM. Slots are a
uniform 258 B because an `AUX_ADV_IND` payload can reach 255; primary PDUs use
~40 of it.

What stays on the capture path, and why:

- **Repeat throttling** (`note_and_throttle` / `stats_record`) — suppressed
  repeats never reach the queue, so slots are not spent on frames that get
  discarded.
- **Nothing for the LED.** `led::sniff` polls two atomics on its own 1 ms frame
  (below), so the indicator costs the capture path a `fetch_add` per packet and
  nothing else — the per-packet blink included, since it is derived from the
  same counter the rate colour is.
- **AuxPtr extraction and `follow_aux`** — the follow decision must be ready by
  the end of the iteration, since RX has to open at
  `t_ref + offset − AUX_OPEN_LEAD_US`.
- **The aux diagnostics** (`aux_miss`, `aux_skip_coded`, `aux_adi_mismatch`,
  `aux_max_hops`) go straight to `log_send`, so each carries the instant the
  chain reached that state and lands ahead of the packet lines it describes.

`decoder::walk_ext_hdr(p, log)` is one walker behind two entry points —
`parse_ext_hdr` (capture path, silent) and `decode_ext_adv` (log task, prints) —
so the two readings of the same header cannot drift apart.

A full queue drops the packet and bumps `dropped` in `Stats`, surfaced in the
`stats:` line. Blocking would defeat the purpose; silent loss would hide it.
`dropped=0` in normal operation.

**The XIP lookups are not the bottleneck — measured, refactor rejected
(2026-08-04).** A profiling build (DWT cycle counter, 64 MHz, wrapped around
`emit_packet` and the three `asset::` lookups) reported per-window decode and
XIP wall-clock in the `stats:` line over a busy 594-window capture. Decode ran
at 30.8–48.3% of wall clock (avg 38.7%); the XIP lookups were 19.3% of decode
(~7% of wall clock), ~170 µs per packet, ~250 µs per lookup — matching the
single-IO 32 MHz block-scan estimate. `dropped` was 0 in every one of the 594
windows, and busier RF raised the lookup count without ever forcing a drop
(corr(pkts, xip_us)=0.43, corr(dropped, xip_us) undefined — `dropped` is a flat
0). Since the drain keeps up, moving lookups off XIP was rejected: a per-lookup
`Qspi::read().await` is *slower* (260 µs–1 ms DMA vs 250 µs XIP) and would ripple
async through the no-alloc `dyn VendorDecoder` registry (~30 files), and a
high-priority SWI scan/drain executor solves a loss problem that does not exist.
The synchronous memory-mapped lookups stay. The profiling instrumentation was
temporary and has been removed.

### Aux following

The `AuxPtr` `offset_us` is measured **from the start of the `ADV_EXT_IND` on
air**, not from when code acts on it. Scheduling is therefore absolute:

- Capture `Instant::now()` when `EVENTS_END` fires in `scan()`, and derive the
  air-start `t_ref = t_end − (10 + len) · 8 µs` (1M: 1 preamble + 4 AA + 2 hdr +
  len + 3 CRC bytes, at 8 µs/byte).
- Schedule with `Timer::at(t_ref + offset − AUX_OPEN_LEAD_US)`. Whatever work
  runs between reception and `follow_aux` leaves the window where it is, which
  is what makes a short-offset aux reachable at all.
- Thread `t_ref` across chain hops: after each aux,
  `t_ref = t_aux_end − (10 + len) · per_byte` (8 µs/byte on 1M, 4 on 2M).

**Configure the radio before the wait, not after.** Everything from the disable
through the SHORTS write is register traffic with no dependence on the clock;
`TASKS_RXEN` is the only thing that has to happen at the deadline, so it is the
only thing left after `Timer::at`. Run after, the retune landed *inside* the
window: the await yields to the decode task, which runs for as long as it runs,
and the receiver opens late by that much. This is safe across the yield only
because the scan task is the sole owner of the RADIO in sniff mode — the decode
and log tasks never touch it.

| constant | value |
|---|---|
| `AUX_MAX_HOPS` | 4 |
| `AUX_OPEN_LEAD_US` | 300 |
| `AUX_RX_WINDOW_US` | 2500 |
| `AUX_MAX_LEAD_US` | 60000 |

`Instant − Duration` underflow is not a concern: uptime greatly exceeds these
microseconds by the time the radio runs.

Hardware-verified (2026-07-28, 717 follow attempts): 419 crc=ok and decoded
(58.4%), 37 crc=err (5.2%), 261 `aux_miss` (36.4%), 0 mismatch — 419+37+261=717
exactly. Observed offsets are short (420/870/1290 µs) and are now the bulk of
both traffic and captures.

A longer capture (2026-08-03, 1325 s, 6830 attempts) put the rate at 43% and
showed where it goes: hit rate falls with offset — 59% under 500 µs, 30–34% at
2–4 ms — and 1M beats 2M 48% to 31%. Signal strength matters (31% at −85 dBm vs
51% at −55) but does not explain the offset gradient, and the duplicate-ADI
hypothesis is refuted outright (zero repeats within 20 ms). The gradient is what
motivated moving the configuration ahead of the wait: the buckets that never
yield are the buckets that hit. Re-measure against this 43% baseline — the
ms-resolution timestamps in the log cannot resolve a 300 µs overshoot directly,
so the hit rate per offset bucket is the instrument.

### Throttling and stats

`SEEN` is a 48-slot cache matched on **payload hash first, not address**, so a
device rotating its resolvable private address while re-advertising the same
payload collapses to one entry instead of producing a "new" line per rotation.
One line still prints every `REPEAT_NOTICE_EVERY = 16` repeats.

A `stats:` line every `STATS_CYCLES = 20` cycles reports
`cycles / pkts / crc_ok / strongest / suppressed / dropped / torn / salvaged`,
all of which describe the window that the line then resets.

### There is no on-device count of devices

An earlier build carried an address table (`devices.rs`) reporting an all-time
unique count and a 60-second live window. It is gone, because in a real
environment neither number could be made honest in the RAM available.

A measured 32-minute urban capture saw ~650 new addresses per minute, 90% of
them appearing exactly once, because a device using a resolvable private address
rotates it roughly every 15 minutes and each rotation is a new key. A since-boot
total therefore counts rotations, not devices: the table finished that capture at
`uniq=27,350` with `evict=25,302`, so 92% of the "unique" figure was the same
2,048 slots being recycled. Sizing the table up does not converge either — an RPA
population is unbounded by construction, and the ~120 KB of RAM not already spoken
for buys about ten minutes of arrivals.

The live window was the salvageable half, but it is not worth 48 KB and a hash
probe on the capture path to report a number the host can compute exactly from the
log it is already receiving. Address-level analysis belongs in
`~/projects/reports/analysis`, which has the whole stream and no memory ceiling.
Resolving RPAs back to a stable identity needs the peer's IRK; see the
`resolve-identities` feature.

`SEEN` remains, and is not a device table: it is keyed on the payload hash, holds
48 slots, and evicts the *least* chatty entry — the right choices for suppressing
repeats, and the wrong ones for counting anything.

### The onboard LED shows rate, liveness and loss

`led::sniff` drives the LED on three separate axes, and reads nothing but two
monotonic atomics — `ble_sniff::PKT_TOTAL` and `ERR_TOTAL`. It renders on a 1 ms
frame and resamples the rate every fiftieth frame, so the EWMA still sees the
50 ms window it was fitted on.

- **Liveness is the blink.** Dark is the resting state and a packet lights the
  frame it landed in, one millisecond. Nothing paces the gap between blinks, so
  the dark is a report on the air rather than on the renderer: a wedged capture
  goes dark and stays dark, which is the thing a steady colour cannot say —
  wedged and healthy both just glow.
- **Rate is the blink's colour**: a blue-green mix over an EWMA of packets per
  second, linear in the rate — pure blue at nothing, cyan at `RATE_MAX / 2`,
  pure green at `RATE_MAX` or above. Duty carries the rate a second time, since
  a busier air lights more of the milliseconds; past ~1000 pkt/s the blinks
  merge and the LED is simply on.
- **Loss is a 1 ms red frame** whenever `ERR_TOTAL` moves — a dropped log line,
  a full decode queue, a torn DMA snapshot, a `radio_stuck`. It replaces the
  blink colour instead of blending into it, so it reads as a blip and not a
  colour shift. Rate and loss are sampled on the same 50 ms window, so a burst of
  a thousand errors is one flash: the LED says loss is happening and roughly how
  often, and the log says how much.

The three are ranked rather than blended — flash, then blink, then dark. The two
lit states stay apart by colour and by rhythm: blinks follow the traffic where
the flashes are bursty, and in a busy environment `ERR_TOTAL` moves at only
~2 Hz against hundreds of blinks a second (a 29.8-minute capture logged 2,695
`torn` and 903 `radio_stuck` against 0 `dropped`).

Only a change is written to the PWM, so an idle LED costs nothing per frame and
a blink costs two `Pwm::set` calls. At the 542 pkt/s a real capture sustains,
about 42% of frames carry a packet, which is roughly 840 updates per second. Each
`Pwm::set` is now a fire-and-forget DMA kick — a handful of register writes, no
busy-wait — so the ~5% of the CPU the 64 µs per-update spin used to cost is gone;
what remains is the `fetch_add` on the capture path and the 1 ms frame itself.

`RATE_MAX = 640` is the scan loop's ceiling, not the air's: a busy-street capture
sustains 467 pkt/s, about three quarters of what the loop can deliver, so full
green stays just out of reach of an ordinary environment and the whole range
stays in use. That capture reads `rgb(0, 89, 131)`, roughly three quarters of the
way from blue to green.

**The two channels split a fixed luminance budget, in emitted light rather than
in duty.** Green takes `pos/512` of it and blue the remainder, and each share is
square-rooted on the way out so it survives the gamma `Pwm::set` applies:
`g = √(255²·pos / (512·LUM_G))`, `b = √(255²·(512−pos) / 512)`. Full blue sets
the budget, `LUM_G = 6` is how much more light the green die makes at equal duty,
and the result holds one apparent brightness end to end — measured flat within 2%
across the fade, green ending at 16.6% duty and blue starting at 100%. Doing the
same split in the perceptual domain instead looks correct term by term and is
wrong, because perceived brightnesses do not add: it lands the green end at 2.7%
duty and dims the LED sixfold on the way there, which reads as a rate signal of
its own.

`EWMA_SHIFT = 4` (α = 1/16, τ = 800 ms) is fitted rather than chosen, by
one-step-ahead prediction error over two captures totalling 35 minutes — the
criterion that needs no reference series, since the best estimate of the current
rate is the one that best predicts the next tick. The optimum is a broad basin at
shift 4–5 (RMSE 104.0 and 105.4 pkt/s on the recent capture, 83.9 and 83.8 on the
long one) and everything from 3 to 6 lands within 1.5% of it; past ~3 s the
estimator starts visibly lagging the room. Log-derived counts are scaled up by
the measured logged-line fraction first — 71.6% and 83.4% in those two captures,
the rest being repeat-suppressed packets that never get a line.

The cost of a linear scale is flicker at the top: `dpos/drate` is three times
what a logarithmic ramp gives at 470 pkt/s, so the residual hue wobble is 3.7% of
the fade on the long capture and 9.4% on the shorter, noisier one, against ~1.5%
under a log ramp. Shift 5 is equally well fitted and takes about a sixth off
that, if the shimmer matters more than the extra 800 ms of lag.

The earlier scheme lit a colour per received packet, signalled from the capture
path. At the measured rates that is a blur at any distance — it confirmed the
radio was alive and nothing else, and it put a `Signal` write on the capture
path to do it.

### The raw hex dump is a fallback, not a footer

A packet that decoded cleanly does not get dumped. Every byte of it is already
named in the lines above, so the dump was pure duplication — and it was roughly
half the bytes leaving the device, which is what capped the capture rate against
the ~285 KB/s CDC ceiling (below).

It still prints for everything the decoders could not account for: a bad CRC, a
PDU type with no decoder, a truncated AD structure, an extended header claiming
more bytes than arrived. Those are the cases where the raw bytes are the only
record of what was received, which is the whole reason the dump exists.

"Accounted for" is reported by the decoders rather than inferred from which
branch the caller took, because a decoder that bails halfway is exactly when the
bytes are wanted. `log_ad_structures` returns how many bytes its walk consumed,
so the dump starts at the first byte it could not place: a 31-byte AdvData whose
one structure covers 27 gets a single four-byte line instead of the whole
payload again. A trailing run of zeros counts as consumed — a zero length byte
is the spec's end-of-data marker and the padding behind it carries nothing.
`decode_connect_ind` returns `bool` and the extended walk sets `ExtInfo::ok`;
neither can say *where* it gave up, because a malformed header invalidates every
offset derived from it, so those fall back to dumping from byte zero. The
salvage path reports the same way the clean path does — a salvaged frame whose
AD structures walk is as fully named as any other, and the CRC caveat is already
on its own line.

`decoder::hexdump` groups its 16 bytes per line into two eights, like
`hexdump -C`: the gap is a fixed landmark to count from, so picking byte 11 out
of a row is two short counts instead of one long one.

The dump's ASCII gutter is the only string output. A separate printable-run
extractor used to emit `str p12: "gSAn Yi"` lines beside it; it read the same
bytes the gutter already shows, and on binary payloads its four-alphanumeric
gate passed enough coincidences to make the real hits hard to pick out.

### Measured throughput

Derive throughput from the `stats:` lines, not from counting logged packets:
each line reports a fixed `cycles=N pkts=M`, so `(interval between two stats
lines) / pkts` gives **ms per primary-channel visit**, a metric independent of
how much the log task printed. That is the only clean way to A/B two captures.

**Logged packets are not captured packets** — 14–44% are dropped by
`note_and_throttle` as repeats and never reach the log. In one capture the
logged rate was 217 pkt/s while actual capture was 455 pkt/s. A "ceiling"
derived from log-line gaps comes out roughly 2× too low.

Current state after the async-decode and fast-ramp changes (2026-07-31): median
1.82 ms per visit, 5.45 ms per 3-channel cycle, 550 pkt/s, `dropped=0`.
Remaining fixed overhead is ~125 µs of that 1.82 ms (6.9%): poll latency 75 µs
(4.1%, now the largest term), ramp 40 µs (2.2%), register setup ~10 µs (0.5%).
Halving `PRIMARY_POLL_US` to 75 would recover ~2% for roughly +3% CPU.

**How to A/B a scan-loop change:** capture before and after in the same spot
within the hour; compare median *and* p10 ms-per-visit; bin by `suppressed=`
within each log to kill the throttle-rate confound. An honest effect shows
equally at median and p10, and the per-cycle delta is exactly 3× the per-visit
delta.

### Power

Radio RX duty is ~96% and CPU ~23% in a busy environment. `Config::default()`
leaves DCDC off (`DcdcConfig { reg0: false, reg0_voltage: None, reg1: false }`),
so the board runs in LDO mode at roughly double the datasheet DCDC figures:
RX 1M is 9.9 mA at 3 V on LDO against 4.6 mA on DCDC, and the CPU at 64 MHz from
flash is ~6.3 mA against 3.3 mA. Budget: **~13 mA VDD plus ~8–10 mA of USBD off
VBUS ≈ 21–23 mA at 5 V ≈ 0.11 W.** The async-decode change costs about +1.5 mA
because the radio is on more of the time.

The one large lever is `config.dcdc.reg1 = true` → roughly 6.5 mA VDD. It is a
one-line change, conditional on the XIAO's DCDC inductors being populated.
Note nRF52840 anomaly 122: an activated QSPI costs ~400 µA extra, which
BLE-sniff mode pays because it owns the QSPI driver.

---

## 6. RSSI monitor (`rssi.rs`)

Passive and not demodulating — 64 evenly-spaced `RSSISAMPLE` readings across
2402–2480 MHz roughly every 10 ms, converted to linear power and smoothed with
an EMA, rendered to a WS2812 strip per-channel and to the onboard RGB LED as a
band average (through `led::Pwm`, so the band colour is gamma-corrected like
every other mode's). Each sweep emits one `RSSI [v0,…,v63]` line in dBm, index 0 =
2402 MHz. Noise-floor entropy from the sweep is folded into the shared jitter
PRNG.

---

## 7. GATT central (`gatt.rs`)

The only active mode: survey → `CONNECT_IND` → LL master state machine → L2CAP/
ATT client → GATT walk → teardown.

Two turnarounds are sub-microsecond and are **hardware shorts chains with
`TIFS = 150`**, not software polling:

1. RX `ADV_IND` → TX `CONNECT_IND` exactly T_IFS later, same channel:
   `end_disable` / `disabled_txen` / `txready_start`.
2. Per connection event, master TX data PDU → RX peer reply T_IFS later:
   `txready_start` / `end_disable` / `disabled_rxen` / `rxready_start`.

The hardware path is empirically good on this silicon and the software path is
not, whatever the register-level reasoning suggests. A revision that set
`TIFS = 0` and issued `tasks_rxen` from software right after TX END — on the
theory that listening early and wide beats landing exactly at T_IFS — produced
`EVENTS_ADDRESS` **0 times in 40 events**, every attempt, every peer, while the
`scan_probe` SCAN_REQ→SCAN_RSP diagnostic in the same firmware, using the
hardware chain, got replies (`rsp=2 advs=5`).

**Disarm each direction-flip short once it has fired, never before.** After
TXREADY — the chain is committed to transmitting — drop `disabled_txen`; after
the TX `DISABLED` drop `disabled_rxen` but *keep* `rxready_start`, since TIFS
holds RXREADY off for another 150 µs and clearing it early means the RX ramps
and never STARTs. Writing SHORTS on the TXREADY edge is safe: TXREADY and
TXREADY→START fire together, so START is already triggered. The same rule fixes
the `conn_event` infinite-RX-reloop: drop `disabled_rxen` after the first (TX)
DISABLED, before RX END.

A left-armed `disabled_txen` re-sends `CONNECT_IND` every ~500 µs, and that
corrupts the anchor as well as the air: software reading `EVENTS_END` late
clears the real TX END and timestamps a *retransmission*, so `connect_end` — and
every anchor derived from it — is off by a whole bounce period while the peer
anchored on the first copy.

**The survey dwell tight-polls with no `yield_now`.** Reacting to `EVENTS_END`
has to happen within T_IFS to abort the turnaround on a non-target packet and to
observe TXREADY on a match; yielding hands the executor to the USB logger and
blows past both. USB drains between dwells. The dwell also re-arms and keeps
dwelling until its deadline rather than ending on the first END from any device
— breaking out early turns a 60 ms dwell into ~1 ms in a busy band, and the
target is then almost never heard.

Link parameters: `CONN_INTERVAL = 25` (× 1.25 ms = 31.25 ms = 1024 ticks),
`CONN_TIMEOUT = 300` (3 s), `HOP_INCREMENT = 7`, `ATT_MTU_MAX = 247`,
`RECENT_WINDOW_S = 3600` (a walked device is not re-walked for an hour),
`RETRY_COOLDOWN_S = 60`.

Shared radio codec lives in `common.rs`. GATT/ATT decode stays in `gatt.rs`:
`decoder::uuid_name` covers SIG 16-bit UUIDs but not GATT declaration,
characteristic or descriptor UUIDs.

**Interpreting probe results:** one `rsp=1` is not a working turnaround. A
single-config, single-shot probe reading `rsp=1` was taken as "radio path OK"
and sent a debugging session sideways; over 12 probes it was 1/12, the luck rate
of a broken turnaround. Sweep configs side by side against the same peer and
count attempts.

### Wall-clock harvested from a peer's Current Time Service (`wallclock.rs`)

Every firmware timestamp is an embassy `Instant` — µs since boot, no calendar.
The GATT walk already reads every readable characteristic, so when a peer hosts
the SIG Current Time Service the date is *already on the wire*; we just decode it.
`read_value` recognizes the three Date-Time-bearing characteristics by their
16-bit UUID — `0x2A2B` Current Time, `0x2A0C` Exact Time 256, `0x2A08` Date
Time, all sharing the 7-byte Date Time prefix — gates the value for plausibility
(`year 2000..=2100`, month/day/hour/min/sec in range), and on a pass emits an
explicit `walltime:` line and calls `wallclock::anchor`.

The anchor stores `wall_epoch - uptime` as a **`u32` Unix-second boot epoch**
(`AtomicU32` + `AtomicBool`, lock-free; `AtomicU64` is not lock-free on this
core, and `u32` seconds reach year 2106). From then on `write_prefix` renders
every log line as `[YYYY-MM-DDThh:mm:ss.mmmZ]` instead of `[SSSSSS.mmm]` uptime;
the millis come from the line's own `Instant`, the seconds/date from the anchor.
Because the anchor is set *before* the `walltime:` line is queued, that line's
own prefix is already wall-clock — self-checking.

Deliberately **seconds-granularity**: the anchor drops the sub-second phase of
the observing `Instant`, so it carries up to ~1 s of jitter. Good enough to date
a capture, not a disciplined clock (fractions256 is logged, not used). The anchor
is RAM-only — a reboot clears it and it is relearned on the next Current Time
read; there is no battery-backed RTC. Purely opportunistic: a peer that gates
`0x2A2B` behind pairing simply yields no time, no harm. The same `read_value`
hook also decodes other broad SIG known-values (DIS strings, Battery, Appearance,
Preferred Conn Params, PnP ID, System ID) to a labelled line, falling back to the
hex dump when the UUID is unrecognized.

---

## 8. Connection follow (`conn_follow.rs`)

Passive. Takes the connection parameters from a captured `CONNECT_IND`, retunes
to that access address and CRC init, and hops the 37 data channels in lockstep,
capturing the central's packet and the peripheral's T_IFS reply each event. It
parses and applies `LL_CONNECTION_UPDATE_IND`, `LL_CHANNEL_MAP_IND` and
`LL_PHY_UPDATE_IND` at their correct effective connection events.

### Ending a follow

There is no wall-clock cap. A live connection is followed for as long as it
lives, which means advertising discovery is suspended for that whole time; what
bounds it is the same supervision counter the peers use,
`supervisionTimeout / connInterval` consecutive missed events. That counter fills
as soon as the link goes quiet, including when the `LL_TERMINATE_IND` that ended
it was encrypted and so invisible to us.

The `FOLLOW end reason=` tag distinguishes five outcomes:

| reason | meaning |
|---|---|
| `terminate` | saw a plaintext `LL_TERMINATE_IND` |
| `supervision` | silence after a clean lock — the connection ended and we followed it to the end |
| `desync` | the miss counter filled while the link was provably still on air: we never locked, or `EVENTS_ADDRESS` kept firing through the outage. A bug in our timeline, not the end of a connection |
| `phy-unsupported` | an asymmetric or Coded `LL_PHY_UPDATE_IND` (see below) |
| `bad-channel` | channel selection produced no usable channel |

Splitting `supervision` from `desync` is what makes a capture self-diagnosing:
both are "we stopped receiving", but only one of them is our fault.

The reason describes the *terminal* outage only, which is why `relock=` is also
on the closing line. A follow that locked, lost it, and relocked a dozen times
before dying was desynced for most of its life even though the last outage ran a
full supervision timeout and so earns the `supervision` label honestly. The
counter is the signal there; earlier relocks are deliberately not folded into
the reason, because a link that flaps once and then genuinely disconnects is
ordinary and would be mislabelled by it.

Miss lines are throttled once the lock is gone — every miss while still locked,
then one in 64. A desynced follower on a 7.5 ms interval emits ~130 a second;
unthrottled, one outage buries the packets around it and puts line formatting in
every event. `lost lock` marks where each run began and `miss_addr` /
`miss_silent` count them all.

### The LED reports lock, not activity

The follower drives `led::Gpio` directly — one register write per channel, no DMA
— because the LED is updated inside the event loop, between a reception and the
next window opening, where the simpler write fits better than aiming a DMA at a
sequence buffer. It also needs only the eight corners of the cube, which is all
`led::Gpio` renders.

Blue and red are one axis and hold their state: blue for an event we captured,
red for one we missed, each written when the event resolves and left alone until
the next one does. That makes an outage solid red for its whole length and a
single dropped event one red blink, which is the distinction that matters when
watching a follow with no console attached — a desynced follower and a healthy
one on a quiet link both stop printing, and only the LED separates them
immediately.

Green is the other axis and flashes for one event whenever that event carried a
payload, master or peripheral. It is deliberately not per-packet: every
connection event has a master packet, and on an idle link nearly all of them are
empty PDUs, so flashing on all of them would hold the LED cyan for as long as
the follow is healthy and report nothing. Tying it to the payloads makes the
flashes count the same packets the log prints.

Before the first lock the LED sits red, because hunt mode is not tracking
anything yet. A follow always exits with all three channels cleared, so the mode
returns to its listening state — dark, blinking blue per advertising packet —
rather than leaving a lock colour lit after the lock is gone.

### Connection updates: WinOffset moves the anchor

At the instant, `WinOffset` shifts that one event's anchor forward by
`1.25 ms + WinOffset × 1.25 ms` — the transmit-window delay plus the offset,
exactly as the first anchor after `CONNECT_IND` is built (Core v5.4 Vol 6
Part B §5.1.1). Only `WinSize` of width is left to hunt across, and the next
event re-anchors off the captured packet as usual.

An earlier revision left the anchor alone and widened the instant event's window
by the offset instead, on the reasoning that re-anchoring would absorb the shift
once the packet landed. It reaches the packet only while the offset fits inside
the span cap of three quarters of an interval, and a real Apple TV link
negotiated `WinOffset` = 6.25 ms against a new interval of 7.5 ms — a required
reach of 7.5 ms against a 5.625 ms cap. The instant was missed, and `anchor` was
then a whole new interval behind the event counter: from that point the radio
sat at event *N−1*'s time on event *N*'s channel, which is the same
self-consistent off-by-one the hunt-window cap exists to prevent. The capture
degenerated into 1486 silent misses and 12 accidental relocks over the following
1492 events, and died on supervision timeout.

### PHY updates

`LL_PHY_UPDATE_IND` switches the RADIO between the 1M and 2M uncoded PHYs at its
instant, which also changes the air-time constant the anchor is re-derived from:
1M is a 1-byte preamble at 8 µs/byte, 2M a 2-byte preamble at 4 µs/byte, so
`air_us` is `(10 + len)·8` and `(11 + len)·4` respectively. Getting that wrong
offsets every anchor by the difference. Applying a switch also drops back into
hunt mode for one event rather than trusting a window sized for the old PHY.

Only a symmetric switch is followed. One radio has one `MODE`, and an asymmetric
link would need it rewritten inside the 150 µs hardware turnaround between the
master's packet and the reply — which the shorts chain performs and software
cannot reach into. Asymmetric or Coded ends the follow rather than spending the
supervision timeout listening on a PHY the peers have left. A PHY update that
arrives *after* encryption starts is invisible (the opcode is ciphertext, and
`capture` refuses to act on ciphertext), so that case still desyncs.

### Encrypted payloads

From `LL_ENC_RSP` on, a packet gets its header line — LLID, length and the
sequence flags are all in the clear — and its body dumped raw on `ct+` lines.
Decoding it would only manufacture bogus LL/L2CAP fields, but the bytes are the
entire record of the link from that point and offline decryption needs them. The
dump is dense, 128 bytes to a line rather than `hexdump`'s 16: there are no field
boundaries to line offsets up against and no readable ASCII side, and a 251-byte
PDU in the annotated form is 16 lines — two of those in one connection event
overrun the 32-slot `LOG` channel by themselves. `dropped=` on the closing line
reports it when they still do.

### Channel selection: one bit picks the algorithm

ChSel is bit 5 of the advertising PDU header. The initiator sets it in
`CONNECT_IND` only when the advertiser also advertised CSA #2 support, so that
single bit decides the hop algorithm for the whole link — and it is the reason
`parse_connect_ind` takes `buf[0]` alongside the payload. `ConnSpec::csa2`
carries it, `decode_connect_ind` prints `csa=1`/`csa=2`, and the `FOLLOW` line
repeats it.

The two algorithms differ in what state the follower must carry:

- **CSA #1** (`csa1_channel`) walks `unmapped = (unmapped + hopIncrement) % 37`
  forward one step per event, so the index has to be advanced for every event —
  including the ones the catch-up path skips.
- **CSA #2** (`csa2_index`) is a pure function of the event counter: `chid` is
  the two halves of the access address XORed, `prn_e` is three rounds of
  permute-then-MAM over `counter ^ chid`, and the channel is `prn_e % 37`, or —
  when that index is unused — the `(numUsed × prn_e) >> 16`-th channel in the
  map. Skipping events costs only an advance of the counter.

**The CSA #2 arithmetic is pinned at compile time.** `const _: () = { … }` in
`conn_follow.rs` asserts the Core spec's own sample data (Vol 6 Part C §3):
access address `0x8E89BED6` → `chid = 0x305F`, counters 0/1/2/3 → channels
25/20/6/21 on a full map, and counters 6/7/8 → 23/9/34 on a 9-channel map that
exercises the remap branch. This is the rare part of the follower whose
correctness is arithmetic rather than RF, so it is settled by the compiler; a
wrong constant would otherwise reach the bench looking exactly like an anchor
error.

### The hunt window is bounded well short of one interval

Until the first capture there is nothing to re-anchor to, so the follower widens
its receive window. **That widening must stay well short of one `connInterval`.**
A window spanning `anchor[N] → anchor[N+1]` does contain a master transmission —
event *N+1*, while the radio is tuned to event *N*'s channel. Once the
prediction is even slightly late, every event slips one slot and the mismatch is
self-consistent forever.

Evidence (2026-07-29): 0 packets in 24 events on a 24-channel map, and exactly
2 in 29 on an 8-channel map — the hit rate CSA #1 remap collisions produce on
their own, since `unmapped % numUsed` maps many indices to the same physical
channel. The follower was only ever receiving when two adjacent unmapped indices
happened to collide.

The underlying slip: `RX_LEAD_US` was 200 µs against a measured 368 µs late,
because `connect_end` is timestamped by a software poll of `EVENTS_END` rather
than a hardware capture, and the `CONNECT_IND` decode and log run before
`follow()` is entered. Current shape:

| constant | value |
|---|---|
| `RX_LEAD_US` | 1200 |
| `MASTER_TAIL_US` | 1500 |
| `HUNT_TAIL_US` | 2500 |
| `SLAVE_SPAN_US` | 700 |
| `RESYNC_AFTER_MISSES` | 2 |

The hunt window is `RX_LEAD_US + MASTER_TAIL_US + HUNT_TAIL_US + transmit
window`, capped at one interval, re-applied every event until lock. A
phase-preserving catch-up at the loop top skips **whole intervals** — advancing
`ev` and the CSA #1 hop together — whenever the anchor falls behind the clock.

**`synced` is not a one-way latch.** `RESYNC_AFTER_MISSES = 2` drops back into
hunt mode. Without it, the first captured packet narrowed the window to
`[−RX_LEAD_US, +MASTER_TAIL_US]` (~2.7 ms) permanently, and a later slip — an
unparsed connection update, a master re-anchoring on its own schedule, or
re-anchoring on a later PDU of a multi-PDU event — could never be widened out
of. Capture 2026-07-29: locked at ev1 (offset +762 µs), recaptured at ev7 with
the offset moved to −701 µs, then 24 consecutive misses to supervision timeout,
with the channel sequence perfectly correct throughout.

**Telling wrong-channel from wrong-time.** Both give a hit rate near
`1/numUsed`, so the count alone does not discriminate. A third cause has the
same signature — following a CSA #2 link with the wrong algorithm — and the
`csa=` field on the `FOLLOW` line rules it in or out before any of the analysis
below is worth doing. Test the off-by-one
hypothesis directly: compute where `ch[N] == ch[N+1]` in the CSA #1 sequence and
check whether the observed hits fall there. In the capture above the hits were
at ev1/ev7 while off-by-one predicted ev14/ev21, which ruled out channel
misalignment and pointed at the anchor.

The ChM hex is printed `chm[0]..chm[4]`, spec octet order (chm[0] bit 0 =
channel 0), in all three sites — the `decoder/mod.rs` `CONNECT_IND` dump, the
`conn_follow` FOLLOW-start line and `LL_CHANNEL_MAP_IND`.

---

## 9. IEEE 802.15.4 sniff (`zb_sniff.rs`)

The only non-Bluetooth mode. The nRF52840 RADIO implements 802.15.4 natively —
O-QPSK DSSS, 250 kbit/s, channels 11–26 at 2405–2480 MHz, `(ch - 10) * 5` as the
`FREQUENCY` offset — so this is the same peripheral every other mode drives, with
a different `MODE`/`PCNF`/`CRC` block. One RADIO and one `MODE` register means it
cannot coexist with the BLE modes, hence a boot mode rather than a task.

### `radio_configure_154` — the four settings that silently deafen the receiver

Register values transcribed from `embassy-nrf`'s own
`radio/ieee802154.rs` and checked against PS v1.11. Most of the block is
unsurprising; four fields differ from `radio_configure_ble` in ways that produce
a receiver that never syncs rather than an error:

| field | BLE | 802.15.4 | why it matters |
|---|---|---|---|
| `PCNF1.WHITEEN` | `true` | `false` | 15.4 spreads with DSSS and does not whiten |
| `PCNF1.BALEN` | 3 | 0 | there is no access address; sync is the 1-byte SFD |
| `PCNF0.CRCINC` | exclude | `Include` | the PHR counts the 2 FCS bytes |
| `PCNF0.PLEN` | `_8bit` | `_32bitZero` | four zero preamble octets, then SFD |

Plus `SFD = 0xA7`, `CRCPOLY = 0x0001_1021` (CRC-16-CCITT), `CRCINIT = 0`,
`CRCCNF.SKIPADDR = Ieee802154`, `LFLEN = 8`, `MAXLEN = 127`.

`BALEN = 0` is the one with a downstream consequence. BLE's 4-byte access address
is a 32-bit correlator that rejects noise before a reception ever starts; 15.4
has no per-network sync word at all, so every frame on the channel is offered to
us and the CRC is the only filter. Frames that fail it are counted and never
logged — their bytes are not trustworthy enough to decode. In practice the count
stays low, because SFD detection is a chip-level correlation and not a byte
match; see the liveness table below for why that matters.

**DMA layout** (PS figure 124), which is not the BLE one: `buf[0]` is the PHR,
`buf[1..1+n]` the MAC frame where `n = PHR - 2`, and `buf[1+n]` an LQI byte the
hardware appends. The FCS is verified in hardware and never written to RAM, and
LQI is not computed for frames under 3 bytes.

### Why not `embassy_nrf::radio::ieee802154`

Three reasons, in order of how hard they are to work around:

1. `Radio::new` requires `interrupt::typelevel::Binding<T::Interrupt,
   InterruptHandler<T>>`, and this build cannot wire the RADIO vector — the same
   wall `ble_sniff` hit (§5). Polling sidesteps a known-bad path.
2. It takes `Peri<RADIO>` ownership, which contradicts every existing mode
   driving `pac::RADIO` raw.
3. The energy-detect block (`TASKS_EDSTART` / `EVENTS_EDEND` / `EDSAMPLE`) is not
   exposed by it, and the channel survey is built on it.

The driver source stays the reference for register values.

### `PHYEND_START`, the 15.4 analogue of `END_START`

Continuous reception works exactly as in `ble_sniff`: `RXREADY_START` to begin
sampling at READY, `ADDRESS_RSSISTART` to sample signal strength at SFD match,
and `PHYEND_START` to re-arm in hardware the instant a frame completes. That last
one is what makes acks catchable — an ack airs 192 µs (`aTurnaroundTime`) after
the frame it answers, and a software re-arm cannot make that. The poll interval
is 150 µs, matching the BLE scanner for the same reason.

The copy-out therefore races the next frame's DMA, and is handled the same way:
read the per-frame registers, snapshot into `PKT_BUF`, then re-check
`EVENTS_ADDRESS` to see whether the snapshot was torn. `ADDRESS` does fire in
15.4 mode — Nordic's own driver relies on `ADDRESS_RSSISTART`.

Air time for the timestamp is `(6 + n + 2) × 32 µs` before `PHYEND`: 4 preamble
octets, SFD, PHR, the payload, and the 2 FCS bytes the radio stripped, at 32 µs
per byte.

### Energy detection is the wrong prior for dwell (2026-08-04)

BLE's channel strategy does not transfer. An advertiser rotates across 37/38/39
and the scanner must chase it; an 802.15.4 network picks one channel at
commissioning and stays there for its lifetime, so the strategy is to park. The
question is where.

The first implementation used the ED sweep to decide: `EDCNT = 2`, 128 µs per
sample, ~4.7 ms for all 16 channels, then 120 ms of dwell on any channel 8 dB
above the sweep's own floor and 20 ms on the rest. **That is backwards, and the
first capture said so.** 38 s of it caught nothing, and the reason is visible in
the sweep itself: the persistently flagged channels were 16–19 and 21–24, which
are exactly the 802.15.4 channels overlapping Wi-Fi 6 and Wi-Fi 11.

An ED sample integrates 256 µs. 802.15.4 duty cycles are minuscule — a
mains-powered Zigbee router emits a link-status frame about every 15 s, a sleepy
end device polls every few minutes — so the probability of a sample landing on
one is negligible. Wi-Fi, being continuous, is what ED sees. Biasing dwell toward
ED-hot channels spends the budget on the channels *least* likely to host a mesh.

Dwell is therefore near-uniform: `DWELL_BASE_MS = 50` everywhere, with
`DWELL_PREFERRED_MS = 150` on channels 11/15/20/25 — the ZLL primary channels,
which sit in the Wi-Fi gaps and are what coordinators and border routers pick by
default. Order is reshuffled each cycle with jitter, for the same anti-aliasing
reason `ble_sniff` shuffles.

What matters for time-to-first-frame is **per-channel duty cycle**,
`dwell[ch] / sum(dwell)`, which is independent of the absolute dwell numbers. The
old split gave a quiet channel 20/780 ≈ 2.6%, so a 15 s-period link-status frame
took ~10 minutes to expect. Uniform gives 6.25%, and a preferred channel 12.5%,
putting the same frame at ~2–4 minutes. Either way **this mode is a survey that
needs minutes, not seconds** — a 40 s capture finding nothing is not evidence of
an empty band.

The sweep is still run and still logged: it is the only channel-occupancy picture
Sonde produces, and it is the independent check that the analog receive path
works when nothing decodes — ED cannot produce sane per-channel energy unless the
receiver ramps and tunes. It just does not steer the dwell. `zb_ed` marks a
preferred channel `*` and an ED-hot one `#`.

`ed_dbm` is `-93 + code`, the linear approximation to the 0..63 ED code, used for
ranking only; nothing treats it as calibrated.

### Telling an empty band from a deaf receiver

`frames=0 crc_err=0` is ambiguous, and the first capture produced exactly that.
It is what an empty band looks like and equally what a misconfigured demodulator
looks like, so the stats line carries three fields that separate them:

| observation | conclusion |
|---|---|
| `states` missing bit 3 | the receiver never reached RX |
| `fs=0` | nothing correlates the SFD: demodulator config, or an empty band |
| `fs>0, phyend=0` | frames sync but the capture event is wrong — and `PHYEND_START` is not re-arming either |
| `fs>0, phyend>0, frames=0` | receptions complete and all fail CRC |

`fs` counts `EVENTS_FRAMESTART`, which fires on SFD correlation long before the
frame completes, so it registers sync attempts that never become packets.
`states` is a bitmask of `RADIO.STATE` values sampled during dwells.

An earlier note here claimed `crc_err` would be routinely non-zero because
SFD-only sync lets noise start receptions. That overstates it: 802.15.4 sync is a
DSSS chip correlation across the preamble, not a raw byte match, and Wi-Fi OFDM
rarely demodulates into valid O-QPSK symbols. `crc_err = 0` is normal on a band
with no 802.15.4 traffic, which is precisely why it cannot be used as the
liveness signal.

The one thing ruled out early: **LFCLK drift is not a candidate here.** It broke
`gatt` and `conn_follow` because those schedule a receive window at a computed
future instant (§2). This mode opens the receiver and leaves it open for tens of
milliseconds; a 3100 ppm error changes the dwell length by 0.3% and nothing else.
`LfclkSource::Synthesized` has been set since that bug anyway.

### `CRCSTATUS`, not `EVENTS_CRCOK`

Both are available, and `embassy_nrf`'s driver reads the status register
immediately after `EVENTS_PHYEND` — so the capture path does the same. The event
is a separate signal with its own timing relative to PHYEND; following the
reference implementation removes it as a variable.

### Frame version 2 addressing

802.15.4-2015 replaced the legacy "destination PAN unless suppressed, source PAN
unless compressed" rule with Table 7-2, where the compression bit's meaning
depends on *both* addressing modes, and added sequence-number suppression.
`pan_presence` implements both. This is not optional detail: Thread runs frame
version 2 almost exclusively, and parsing it with the legacy rule mis-frames
every Thread packet by two bytes — which surfaces as plausible-looking garbage
addresses, not as an obvious failure.

The auxiliary security header is parsed too (`7.4`): security level, key
identifier mode, and the frame counter unless suppressed. It is in the clear even
though the payload is not, and the key-id mode fixes the header length —
0/1/5/9 bytes for modes 0/1/2/3 — so getting it wrong misplaces the payload
boundary.

### Beacons are the only frames that name the stack

A secured data frame from Zigbee and one from Thread are identical at the MAC
layer. A beacon payload starts with a protocol ID — `0x00` Zigbee, `0x03` Thread
— so `beacon_stack` walks superframe spec (2 B) + GTS spec (1 B, plus directions
and 3 B per descriptor when the count is non-zero) + pending address spec (1 B
plus 2 B/short and 8 B/extended) to reach it. That answer is attached to the PAN
in the 16-slot network table and inherited by every later frame on that PAN.

The table and the 128-slot device fingerprint set are both fixed-size and
cumulative since boot. Both report saturation rather than truncating silently:
`nets_report` says outright when the table filled, and `dev=` pinned at 128 is
itself the signal that the site is busier than the table can describe.

### The LED must not block the receiver

Green held for the energy sweep, red flashed on each retune, blue flashed per
captured frame. The blinks are one-shot and non-blocking: `Blink::flash` lights
the LED and stores an off-instant, and `Blink::service` — called from the poll
loop that runs anyway — darkens it. The obvious alternative, `set(BLUE)` →
`Timer::after_millis(1).await` → `set(OFF)`, is 1 ms of deafness per frame and
per retune, and it costs exactly the frames that matter most: an ack airs 192 µs
after the frame it answers, so it lands inside the blink and the exchange is
recorded as one-sided.

### Expected yield

MAC headers, always. Payloads, never — AES-CCM* under a network key, and Thread
is opaque without commissioning credentials. A sweep showing only Wi-Fi
(channels 11–14, 16–19 and 21–24 overlap Wi-Fi 1, 6 and 11) is a valid answer
about the environment and also the independent check that the ED path works when
nothing decodes. The most decodable moment a Zigbee network has is a join, which
puts Beacon Requests, beacons and Association Requests in the clear.

---

## 10. Working conventions

**Comments describe what the code does.** Not what it replaced, not what was
deleted, not what it avoids — unless the "not" is itself load-bearing, as with
the ramp-up and MAXLEN rules above, where a future change would otherwise
re-break something.

**Python runs from the project virtualenv:** `.venv/bin/python`, and packages go
in with `.venv/bin/python -m pip install <pkg>`. `scripts/refresh_data.py` needs
`requests`, and the venv's certificate bundle is the one that validates the
upstream downloads.

**Timing changes are verified on hardware, not reasoned about.** Every entry in
this document that reverses an earlier decision does so because a capture
disagreed with the reasoning. Two failure patterns to avoid repeating: recording
an inference as a fact (an earlier note asserted that `Fast` ramp was *required*
for T_IFS, which put `Fast` on every path and broke all three turnarounds), and
sizing an effect from a single trial (`rsp=1`).

---

## Sources

Every figure here comes from a hardware capture, dated in the text. Radio
references are to the nRF52840 Product Specification v1.11; protocol references
to the Bluetooth Core Specification.
