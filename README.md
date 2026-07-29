# Sonde

A five-mode 2.4 GHz radio probe for the **Seeed XIAO nRF52840**, written in
bare-metal Rust on Embassy. A sonde is an instrument you drop into a medium to
sample it and report back, which is what this does: it sits in a room, listens
to the traffic already in the air, and prints what it finds over a USB serial
console.

Four modes cover Bluetooth Low Energy and one covers **IEEE 802.15.4** — Zigbee
and Thread — which the same radio speaks natively at a different modulation.
Four of the five are **passive**: they transmit nothing and are undetectable by
the devices they observe. One mode is an **active central** that forms real
connections and interrogates devices. The mode is selected by reset-cycling the
board, so switching between them needs no reflash.

There are **two builds** of the same code, for two boards. `sonde-usb` (the one
this README mostly describes) runs on the **Seeed XIAO nRF52840** and logs
decoded ASCII over a USB serial console. `sonde-headless` is a **drop-and-collect**
probe — left running on a battery in a space and retrieved later — that runs on a
cheap **nice!nano v2 clone**: it writes raw PCAP/text to an SD card (and exposes
it as a read-only USB drive) with no console. It is the same nRF52840, so the
radio behaviour is identical; only the board plumbing differs.

The firmware drives the nRF52840 RADIO directly rather than through a
SoftDevice, which is what makes the passive modes possible: it can dwell on
arbitrary channels, follow another party's connection, and log timing at
microsecond resolution.

## Overview

What Sonde captures and reports:

- **Advertising traffic** on the three primary channels, including BLE 5
  extended advertising followed through `AuxPtr` chains onto the secondary data
  channels.
- **Decoded advertising payloads.** A dispatch registry of 45 vendor decoders
  (Apple, Microsoft, Xiaomi, Samsung, Huawei, Google Fast Pair, Eddystone,
  BT Mesh, LE Audio, and others) parses manufacturer-specific and service data
  into named fields, alongside the generic AD types — flags, service UUIDs,
  local name, TX power, appearance, class of device.
- **Resolved names** for MAC vendors, SIG company identifiers and 16-bit UUIDs,
  from lookup tables held in external flash (see below). Vendor resolution
  covers all four IEEE assignment sizes, so a MAC inside a subdivided block
  names its actual assignee rather than the registrar.
- **Band occupancy** as a 64-point RSSI sweep across 2402–2480 MHz.
- **Live connections**, either followed passively after catching the
  `CONNECT_IND`, or established directly and walked as a GATT client.
- **IEEE 802.15.4 networks** on channels 11–26: per-channel energy, PAN IDs,
  device addresses, frame types and the auxiliary security header. Payloads are
  AES-CCM* encrypted under keys Sonde does not have, so this reports presence
  and topology rather than content.

Every observation is timestamped at the moment it is queued, not when it reaches
the host, so a slow USB drain never disguises itself as an event-timing
anomaly.

## Architecture

```
assets/     upstream data: four IEEE MAC registries + Bluetooth SIG YAMLs
firmware/   the Sonde firmware (Cargo package `sonde`, thumbv7em)
  build.rs    parses ../assets/ into internal search indices + the QSPI image
  memory.x    linker script; app region ends at 0xEC000
  src/
    main.rs        boot-mode selection, USB CDC logger, PRNG
    led.rs         onboard RGB LED: PWM mixing, blink patterns, indicator tasks
    common.rs      shared RADIO setup: BLE PHY, whitening, CRC, channel maths
    ble_sniff.rs   passive advertising scan + AuxPtr following
    rssi.rs        passive spectrum sweep + WS2812 visualisation
    gatt.rs        active central: connect and walk the attribute database
    conn_follow.rs passive connection following (CSA #1 and #2)
    zb_sniff.rs    passive IEEE 802.15.4 survey: energy sweep + MAC decode
    decoder/       AD parsing, 45 vendor decoders, hexdump, asset lookups
      asset.rs       XIP read path for the offloaded tables
builder/    host tool: `uf2` (ELF to UF2) + `provision` (asset streamer)
scripts/    build / flash / provision / refresh helpers
docs/       DESIGN-NOTES.md: internals and the measurements behind them
```

The sections below describe Sonde from the outside. For the register-level
detail — radio ramp-up and T_IFS rules, the scan loop's timing budget, clock
accuracy, and the hardware captures each of those rests on — see
[docs/DESIGN-NOTES.md](docs/DESIGN-NOTES.md).

The root is a virtual Cargo workspace. `.cargo/config.toml` pins the firmware to
`thumbv7em-none-eabi`, which applies to every cargo invocation from the root —
so the host-side `builder` crate is built with an explicit `--target <host>`.
The wrapper scripts resolve that tuple at runtime with `rustc --print
host-tuple`, so nothing is pinned to a particular host architecture and the
tooling works on macOS and Linux alike. Build `builder` through the scripts
(`scripts/run-builder.sh`, `scripts/provision.sh`) rather than with a bare
`cargo build` from inside `builder/`, which would inherit the cross target.

### Concurrency

Embassy's thread-mode executor runs the mode task alongside the USB device task,
the CDC drain task and the LED indicator task. The log path is a bounded
32-deep channel of 512-byte lines; `try_send` never blocks, so a radio deadline
is never missed waiting on USB. Lines are dropped rather than delayed when the
host cannot keep up.

Timing comes from `embassy-time` on RTC1. LFCLK is configured as **Synthesized**
— divided from the external high-frequency crystal — because the internal RC
oscillator measured ~3100 ppm slow on this board, roughly six times the total
error BLE permits, which is enough to walk a connection anchor out of the peer's
receive window within ten events.

### QSPI asset offload

Name resolution needs large tables — four sections, 839 KB packed:

| Section | Contents | Size |
|---|---|---|
| `oui` | IEEE MA-L, 39826 organisations by 24-bit OUI | 492,954 B |
| `ouisub` | IEEE MA-M + MA-S + IAB, 18210 organisations under 439 subdivided OUIs | 250,081 B |
| `company` | SIG company identifiers | 87,652 B |
| `uuid` | 16-bit service / member / SDO / characteristic / descriptor names | 28,158 B |

These live in the XIAO's on-board **2 MB QSPI flash**, memory-mapped for
execute-in-place at `0x1200_0000`, which keeps the firmware image itself down to
~208 KB.

The split is deliberate. `build.rs` parses the source data at compile time and
emits two things:

- **Into the firmware image**, small search structures only: a byte-pair-encoding
  alphabet and dictionary shared by both vendor sections, the 439 subdivided OUIs
  and the 5 of them carved at 36 bits, plus a sparse `(key, offset)` checkpoint
  index for each of the four sections.
- **Into `target/assets_blob.bin`**, the bulk name data, packed as runs of
  `[delta-key varint][length u8][bytes]` records. The delta resets every 64
  records so that any block decodes from its own index checkpoint alone.

A lookup binary-searches the internal index down to a 64-record block, then
scans that block directly out of the XIP window. Nothing is allocated and
nothing is copied.

**Subdivided OUIs.** IEEE issues MAC blocks at four sizes — MA-L (24-bit),
MA-M (28-bit), MA-S and IAB (36-bit) — and the MA-L listing names a subdivided
block "IEEE Registration Authority". Resolving such an address takes the 12 bits
below the OUI, so `oui_vendor` runs two stages: the MA-L search, then, when the
OUI is one of the 439 subdivided ones, a second search of `ouisub` keyed by
`(parent ordinal << 12) | extension`. The ordinal is the parent's position in
the internal sorted list, which fits a 36-bit prefix into a `u32` key and keeps
records dense enough for one-byte deltas. An unassigned sub-block falls back to
the block holder's name.

The image is streamed to external flash once, over USB, by the host
`builder provision` subcommand. Its header — magic, length, CRC32 — is written
**last**, so an interrupted transfer leaves an image that fails validation
rather than one that is valid but partial. A lookup against an unvalidated
image returns `None` and the decoder falls back to printing the raw identifier.
The data survives resets and firmware reflashes; reprovisioning is only needed
after the source data or the packed format changes.

### Boot-mode persistence

The active mode is stored in a 4 KB flash page reserved at `0xEC000`, above the
app region carved out in `memory.x`. It is not stored in RAM: the XIAO's UF2
bootloader runs on every reset with its stack at the top of RAM, clobbering any
retained cell parked there, and it does not preserve `GPREGRET` either.

Each boot appends the new mode to the next free 4-byte slot in the page. That is
a single word write with no erase, so the page is erased about once per 1024
reboots. Unrecognised contents — stale bytes from an older build, or a torn
write — are treated as corruption and restart the log.

## Modes

The mode advances on **every reset**, cycling through the five below. A cold
power-up starts at BLE sniff. A one-second onboard-LED flash immediately after
reset identifies the mode that is about to run.

### 1. BLE sniff — passive (boot LED: blue)

Pure listening. The radio never transmits in this mode.

Dwells on the three primary advertising channels (37/38/39, LE 1M), decoding
every PDU it receives. When it sees an `ADV_EXT_IND` carrying an `AuxPtr`, it
follows the pointer onto the secondary data channel to capture the
`AUX_ADV_IND`, and continues through `AUX_CHAIN_IND` fragments — up to four
hops. Aux reception is scheduled from the captured air-start timestamp of the
extended advertisement, not from "now", because the offset in the pointer is
relative to the original transmission.

Per-channel dwell is jittered and the channel visit order is reshuffled every
cycle. A fixed scan cadence aliases against an advertiser's fixed advertising
interval, and the failure mode is silent: you land in the gaps forever and
conclude the device is not there.

The onboard LED reports the capture, not individual packets: a blue-green mix
over a smoothed packets-per-second rate, blue at nothing, cyan at 320/s and green
at 640/s — interrupted by a 10 ms red flash whenever anything is lost (a dropped
log line, a full decode queue, a torn DMA read, a stuck radio). The two channels
split a fixed light budget, so the LED holds one brightness and only its hue
moves.

This is also the only mode that mounts the QSPI driver, so it is the mode that
accepts provisioning.

### 2. RSSI monitor — passive (boot LED: green)

Pure listening, and not even demodulating — it samples the receiver's signal
strength indicator without attempting to decode anything.

Sweeps 64 evenly-spaced points across 2402–2480 MHz roughly every 10 ms.
Each reading is converted to linear power and smoothed with an exponential
moving average, then rendered two ways: onto an external WS2812 strip
per-channel, and onto the onboard RGB LED as a band average, on a
green (strong) to blue (mid) to red (weak) scale.

Each sweep also emits one self-describing log line:

```
RSSI [v0,v1,...,v63]
```

Values are dBm; index 0 is 2402 MHz and index 63 is 2480 MHz. Noise-floor
entropy from the sweep is folded into the shared jitter PRNG.

### 3. GATT enum — ACTIVE (boot LED: red)

The one mode that transmits. It surveys for connectable advertisers, sends a
real `CONNECT_IND` to the strongest one, and becomes a BLE central on a live
link. Target devices see a connection and will log it as such.

Once connected it walks the peer's attribute database: primary services,
characteristics with their properties, descriptors, and the value of everything
readable. Values longer than a single 23-byte ATT MTU are pulled in full with
Read Blob continuation. Where a characteristic supports notify or indicate and
exposes a Client Characteristic Configuration descriptor, Sonde writes the
descriptor to subscribe and then listens for two seconds, hex-dumping whatever
arrives.

Operational details worth knowing:

- The connection access address is randomly generated per link and validated
  against the Core specification's constraints — run length, transition count,
  Hamming distance from the advertising access address.
- Inbound L2CAP frames are reassembled across LLID continuation fragments,
  because the peer is not bound by the MTU Sonde asked for.
- The peer is treated as a bidirectional ATT participant: requests it sends
  during enumeration are answered, and unsolicited PDUs are hex-dumped rather
  than discarded.
- A device whose database has been walked is not walked again for an hour. An
  attempt that produced nothing is retried after a minute.
- There is no pairing, so attributes that require encryption return an ATT error,
  which is printed rather than swallowed.

Enumeration LED states, distinct from the boot flash: green flashes when a
connectable peer is in range, red during a connection event the peer answered,
blue during one it did not, and a yellow flash when an attempt fails.

### 4. Connection follow — passive (boot LED: white)

Listening again, this time to a connection between two other devices. Sonde
transmits nothing and neither peer can tell it is there.

When the advertising scanner catches a `CONNECT_IND`, it hands over the
connection parameters. Sonde retunes to that connection's access address and
CRC init, then hops the 37 data channels in lockstep with the two peers,
capturing both the central's packet and the peripheral's T_IFS reply in each
connection event.

Both hop algorithms are implemented. The ChSel bit in the `CONNECT_IND` header
picks between them: Channel Selection Algorithm #1, which walks a running index
forward by the connection's hop increment, and Algorithm #2, which derives each
channel from the event counter through a pseudo-random function seeded by the
access address. Modern peers negotiate #2, and the algorithm in use is reported
on the `FOLLOW` line as `csa=1` or `csa=2`.

Real devices renegotiate their links within the first second, so the follower
parses and applies the two LL control PDUs that move the timeline —
`LL_CONNECTION_UPDATE_IND` and `LL_CHANNEL_MAP_IND` — each at its correct
effective connection event. Following ends on `LL_TERMINATE_IND`, on supervision
timeout, or at a hard wall-clock cap so that advertising discovery is never
starved.

Timing re-anchors to the actual master packet every event: the follower measures
its air start as the END timestamp minus the computed air duration, and
schedules the next event exactly one connection interval later. Until the first
packet lands there is nothing to anchor to, so it begins in a **hunt mode** with
a widened receive window. That widening is bounded on purpose. A window as wide
as a full connection interval is guaranteed to contain the master's
transmission — but on the wrong channel, because the master has already hopped.
Widen far enough to cover anchor error, never far enough to reach the next
event.

The onboard LED reports the lock. While hunting for a `CONNECT_IND` it blinks
blue on each advertising packet seen. During a follow it holds blue for every
connection event captured and red for every event missed, so a single dropped
event is one red blink and a desync is solid red, with a green flash for each
event that carried a payload. It returns to the blue blink when the follow ends.

### 5. Zigbee sniff — passive (boot LED: cyan)

Not Bluetooth. The nRF52840's radio also implements IEEE 802.15.4 — O-QPSK DSSS
at 250 kbit/s on channels 11–26, 2405–2480 MHz — which is the link layer under
Zigbee, Thread and Matter-over-Thread. Same peripheral, different modulation,
sync word, CRC and whitening setting, so it cannot run alongside the BLE modes
and gets a boot mode of its own.

Each cycle begins with an **energy sweep**: the radio's energy-detect block
samples all 16 channels in about 5 ms and emits one line.

```
zb_ed 11*-91 12:-89 13:-90 14:-92 15*-88 16:-90 17#-61 18#-63 ... 26:-88
```

`*` marks a preferred channel, `#` one sitting at least 8 dB above the sweep's
own quietest channel. Sonde then dwells on each channel in a reshuffled order —
150 ms on channels 11, 15, 20 and 25, and 50 ms on the rest.

Note what the dwell is *not* keyed on: energy. An ED sample integrates 256 µs,
and 802.15.4 duty cycles are tiny — a mains-powered Zigbee router sends a
link-status frame roughly every 15 s — so ED essentially never catches a mesh.
What it reliably catches is Wi-Fi, which is continuous. Dwelling on the loud
channels means dwelling on Wi-Fi. The four channels that do get extra time are
the ZLL primaries, which sit in the gaps between Wi-Fi 1, 6 and 11 and are what
coordinators and border routers pick by default. Every channel is still visited
every cycle.

The sweep is worth reading even when nothing decodes. On a site with no 802.15.4
traffic at all it still shows where the Wi-Fi is — channels 11–14, 16–19 and
21–24 overlap Wi-Fi 1, 6 and 11 — which distinguishes "nothing is here" from "the
receiver is not working."

**Give it minutes.** With a near-uniform split, one channel gets 6–12% of the
listening time, so a frame that airs every 15 s takes a few minutes to expect.
A 40-second capture finding nothing says very little.

Captured frames decode down to the MAC header: frame type and version, sequence
number, PAN IDs, short or extended addresses, and the auxiliary security header
with its security level, key identifier mode and frame counter. Frame version 2
addressing is implemented properly, including the 2015 PAN-ID compression table
and sequence-number suppression, because Thread uses it almost exclusively and
parsing it with the legacy rule mis-frames every Thread packet by two bytes.

```
zb ch=15 -67dBm lqi=232 DATA v2 seq=91 dpan=0x1A62 dst=0x0000 src=0x8F3C sec=L5/K1 fc=48213 ack_req
  +00: 61885B621A00003C8F0D55BC000001    a.[b...<..U....
  sec+000: 28A3...
```

The header goes to the annotated hex dump, which has field boundaries worth
lining offsets up against; the encrypted remainder goes to the dense one.

Beacons are the high-value frame. A data frame from Zigbee and one from Thread
are indistinguishable at the MAC layer, but a beacon payload carries a protocol
ID — `0x00` for Zigbee, `0x03` for Thread — so it names the stack outright. Sonde
walks the superframe, GTS and pending-address fields to reach it, and the answer
is attached to that PAN in a running table dumped periodically alongside the
counters:

```
zb net: pan=0x1A62 ch=15 stack=zigbee frames=1184 best=-61dBm
zb stats: cycles=8 frames=1206 crc_err=41 strongest=-61dBm dev=9 dropped=0 torn=0 fs=1253 phyend=1247 states=0x000C
```

The last three fields are there to keep `frames=0` honest, because an empty band
and a deaf receiver produce the same counters otherwise. `fs` counts SFD
correlations — the earliest evidence that something on air demodulated as
802.15.4 — `phyend` counts completed receptions, and `states` is a bitmask of
radio states seen while dwelling, where bit 3 is RX. `fs=0` means nothing is
syncing; `fs>0` with `frames=0` means something is, and the fault is downstream.

The onboard LED narrates the three phases, which are otherwise indistinguishable
from outside and fail differently: solid **green** for the ~5 ms energy sweep, a
**red** flash on each channel change, and a **blue** flash per captured frame,
dark in between. A board stuck green never finished a sweep; one flashing only
red is sweeping and dwelling but hearing nothing. None of it blocks the receiver
— a flash records when it should go dark and the scan loop's existing 150 µs poll
turns it off, so the LED never costs a frame.

**What this mode will and will not give you.** MAC headers, always. Payloads,
never — they are AES-CCM* encrypted under a network key, and Thread is opaque
without commissioning credentials. If there is no Zigbee or Thread hardware in
range, an energy sweep showing only Wi-Fi is the honest answer, not a failure.
The most decodable moment a Zigbee network ever has is a join: put a hub into
permit-join and the Beacon Requests, beacons and Association Requests that
follow are all in the clear.

## Build requirements

- **Rust toolchain** — installed automatically from `rust-toolchain.toml`, which
  pins the `thumbv7em-none-eabi` target and `llvm-tools`. Edition 2024.
- **`cargo install cargo-binutils`** — provides `rust-objcopy`, used by
  `flash.sh`.
- **`pip install adafruit-nrfutil`** — serial DFU packaging and flashing, used by
  `flash.sh`. A project virtualenv at `.venv/` is the expected home for this.
- **Hardware** — `sonde-usb` runs on a Seeed XIAO nRF52840 with the Adafruit UF2
  bootloader. The RSSI monitor additionally expects a 64-pixel WS2812 strip; the
  other four modes need nothing beyond the board. `sonde-headless` targets a
  nice!nano v2 clone (see below).

`sonde-headless` is built for a different job: a **drop-and-collect** probe you
leave running on a battery in a space, then retrieve and read back later. That
goal drives its hardware choices toward **cheap but still capable** — a
~$5 nice!nano v2 clone rather than the XIAO, no QSPI name tables (decode happens
later, on the host), a plain SD card for storage, and a single LED. It shares the
nRF52840 and bootloader with the XIAO, so the radio is the same; the extra parts
(SD card, and optionally a GPS + RTC for real timestamps) are commodity modules.

Build:

```sh
cargo build --release
```

`build.rs` prints the asset-image section sizes and writes the image to
`target/assets_blob.bin`, where provisioning looks for it.

## Updating the firmware

Two routes. Both need the board in bootloader mode, which is a double-tap of the
reset button.

**Drag and drop.** Build a UF2 image by running the firmware target — its Cargo
`runner` invokes `builder uf2` on the freshly built ELF:

```sh
cargo run --release          # writes sonde.uf2
```

Double-tap reset to mount the `XIAO-SENSE` bootloader drive, then copy
`sonde.uf2` onto it.

**Serial DFU.**

```sh
scripts/flash.sh [device]
```

This objcopies the release ELF to `sonde.bin`, packages it as `sonde_dfu.zip`,
and streams it over serial DFU. `device` defaults to the first USB CDC port on
the machine — `/dev/tty.usbmodem*` on macOS, `/dev/ttyACM*` on Linux.

Reflashing does not disturb the QSPI asset image or the boot-mode page — the
flasher only writes the app region below `0xEC000`.

## Updating the QSPI data

Provisioning is accepted only in **BLE-sniff mode**, which is the mode that owns
the QSPI driver. Power-cycle the board so it comes up cold in BLE sniff, then:

```sh
scripts/provision.sh [--port <device>] [--image target/assets_blob.bin]
```

Without `--port` it takes the first USB CDC port it enumerates —
`/dev/tty.usbmodem*` on macOS, `/dev/ttyACM*` on Linux.

The serial log runs from `PROV_ERASED` to `PROV_OK`, a few seconds in total.
Under the hood this is `cargo run -p builder -- provision`; the wrapper exists to
select the host build target, since the workspace pins the firmware's
`thumbv7em` target.

To pull fresh upstream data first:

```sh
.venv/bin/python scripts/refresh_data.py          # all sources, into assets/
.venv/bin/python scripts/refresh_data.py oui      # or one source by name
```

This fetches the four IEEE MAC registries and the ten Bluetooth SIG
assigned-number YAMLs. Then rebuild and reprovision to apply — `build.rs`
repacks the image, and provisioning writes it out.

Reprovisioning is required after any data or format change: `header_check`
compares the image length against what the firmware was built for, so a stale
image leaves every asset lookup returning `None`.

## Reading the log

The firmware presents a USB CDC serial port at 115200 baud:

```sh
screen /dev/tty.usbmodem* 115200   # macOS
screen /dev/ttyACM0 115200         # Linux
```

Every line carries an uptime timestamp in seconds. Packet dumps use a dual-offset
hexdump with an ASCII gutter; printable strings found in payloads are extracted
and printed separately.

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2026 wsmithril &lt;wsmithril@gmail.com&gt;.
Source: [github.com/wsmithril/sonde](https://github.com/wsmithril/sonde)

The MIT license covers this project's source code. The data files in
[`assets/`](assets/) are redistributed from the IEEE MAC address registries and
the Bluetooth SIG assigned-numbers publications and remain under their
publishers' terms — see [assets/NOTICE](assets/NOTICE).
