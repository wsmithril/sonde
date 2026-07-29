#!/bin/sh
# Convenience wrapper: run the host `builder` crate's `provision` subcommand,
# streaming the generated asset image (OUI / company / UUID tables) to the
# device's external QSPI flash over USB CDC.
#
#   scripts/provision.sh [--port <dev>] [--image target/assets_blob.bin]
#
# Without --port, builder picks the first USB CDC port it enumerates
# (/dev/tty.usbmodem* on macOS, /dev/ttyACM* on Linux).
#
# The workspace pins the firmware's thumbv7em target, so build/run builder for
# the host tuple explicitly (same trick as scripts/run-builder.sh).
HOST=$(rustc --print host-tuple 2>/dev/null || rustc -vV | awk '/^host/{print $2}')
exec cargo run -p builder --quiet --target "$HOST" -- provision "$@"
