#!/bin/sh
# Flash a firmware build over the Adafruit UF2 bootloader's serial DFU.
#
#   scripts/flash.sh [variant] [device]
#
# `variant` is `usb` (default — the USB-CDC console build) or `headless` (the
# SD-capture build). `device` is the serial port of the board — the *running
# firmware*, not the bootloader (default: the first /dev/tty.usbmodem* on macOS,
# /dev/ttyACM* on Linux).
#
# For back-compatibility, if the first argument looks like a device path it is
# taken as the device and the variant defaults to `usb`.
#
# Steps: touch to bootloader, objcopy the release ELF to a raw binary, wrap it in
# a DFU package, then stream it to the board. Override the objcopy binary with
# $OBJCOPY if needed.
set -e

# Resolve variant vs. device from the positional args.
case "${1:-}" in
    /dev/*) VARIANT="usb"; DEV="$1" ;;
    usb|headless) VARIANT="$1"; DEV="${2:-}" ;;
    "") VARIANT="usb"; DEV="" ;;
    *) echo "unknown variant '$1' (use: usb | headless)" >&2; exit 1 ;;
esac

case "$VARIANT" in
    usb)      BIN="sonde-usb" ;;
    headless) BIN="sonde-headless" ;;
esac
ELF="target/thumbv7em-none-eabi/release/$BIN"
OBJCOPY="${OBJCOPY:-rust-objcopy}"

# Resolve the target device: the first USB CDC port the platform names when not
# given — /dev/tty.usbmodem* on macOS, /dev/ttyACM* on Linux.
if [ -z "$DEV" ]; then
    DEV=$(ls /dev/tty.usbmodem* /dev/ttyACM* 2>/dev/null | head -n1 || true)
fi
if [ -z "$DEV" ]; then
    echo "no serial device found; pass one explicitly:" >&2
    echo "  scripts/flash.sh $VARIANT /dev/tty.usbmodemXXXX   # macOS" >&2
    echo "  scripts/flash.sh $VARIANT /dev/ttyACM0            # Linux" >&2
    exit 1
fi

if [ ! -f "$ELF" ]; then
    echo "firmware ELF not found at $ELF — run 'cargo build --release' first" >&2
    exit 1
fi

echo "variant $VARIANT: objcopy $ELF -> sonde.bin"
"$OBJCOPY" -O binary "$ELF" sonde.bin

echo "packaging sonde_dfu.zip"
adafruit-nrfutil dfu genpkg --dev-type 0x0052 --sd-req 0xFFFE \
    --application sonde.bin --application-version 1 sonde_dfu.zip

echo "flashing $VARIANT to $DEV"
adafruit-nrfutil --verbose dfu serial -pkg sonde_dfu.zip -p "$DEV" -b 115200
