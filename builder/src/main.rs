//! `builder` — host-side tool for the Sonde firmware.
//!
//! Subcommands:
//!   * `uf2 <elf>`  — convert a built firmware ELF into `sonde.uf2` (this is
//!                    the firmware target's Cargo `runner`).
//!   * `provision`  — stream the generated asset image (OUI / company / UUID
//!                    lookup tables) to the device's external QSPI flash over the
//!                    USB CDC serial port.
//!
//! Run via the workspace: `cargo run -p builder -- <subcommand> ...`.

mod crc32;
mod provision;
mod uf2;

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let cmd = args.next();
    match cmd.as_deref() {
        Some("uf2") => {
            let elf = args.next().unwrap_or_else(|| usage("uf2 <elf>"));
            uf2::run(&elf);
            ExitCode::SUCCESS
        }
        Some("provision") => {
            // provision [--port <dev>] [--image <path>]
            let mut port: Option<String> = None;
            let mut image: Option<String> = None;
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--port" | "-p" => port = args.next(),
                    "--image" | "-i" => image = args.next(),
                    other => usage(&format!("unknown provision arg: {other}")),
                }
            }
            match provision::run(port.as_deref(), image.as_deref()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("provision failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => usage("<uf2|provision> ..."),
    }
}

fn usage(msg: &str) -> ! {
    eprintln!("usage: builder {msg}");
    std::process::exit(2);
}
