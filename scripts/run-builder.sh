#!/bin/sh
# Cargo `runner` for the firmware target: build the host `builder` crate and run
# its `uf2` subcommand to convert the freshly-built ELF into sonde.uf2.
# Cargo appends the ELF path as the final argument.
#
# There are now two firmware binaries, so select one when running:
#   cargo run --release --bin sonde-usb        # USB-CDC console build (default use)
#   cargo run --release --bin sonde-headless   # headless SD-capture build
HOST=$(rustc --print host-tuple 2>/dev/null || rustc -vV | awk '/^host/{print $2}')
exec cargo run -p builder --quiet --target "$HOST" -- uf2 "$@"
