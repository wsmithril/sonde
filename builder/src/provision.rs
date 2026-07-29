//! Host side of the USB-CDC asset-provisioning protocol.
//!
//! Streams the generated asset image (OUI / company / UUID lookup tables) to the
//! device's external QSPI flash. The firmware side lives in
//! `firmware/src/main.rs` (`provision` task). Protocol (header-last, so a partial
//! write never leaves a valid-looking table):
//!
//!   host → device:  "BSPROV\n" | len:u32 LE | crc:u32 LE           (handshake)
//!   device → host:  log line containing "PROV_ERASED"              (region erased)
//!   host → device:  <len> payload bytes (the sections, no header)
//!   device → host:  log line containing "PROV_OK" or "PROV_ERR"    (result)
//!
//! Device status is reported through the normal serial log stream, so we just
//! scan incoming lines for the tokens above.

use crate::crc32::crc32;
use std::io::Write as _;
use std::time::{Duration, Instant};

const HANDSHAKE: &[u8] = b"BSPROV\n";
const BAUD: u32 = 115_200;
const CHUNK: usize = 64; // CDC full-speed bulk max packet

/// Default image path written by `firmware/build.rs`.
const DEFAULT_IMAGE: &str = "target/assets_blob.bin";

pub fn run(port: Option<&str>, image: Option<&str>) -> Result<(), String> {
    let image_path = image.unwrap_or(DEFAULT_IMAGE);
    let payload = std::fs::read(image_path)
        .map_err(|e| format!("cannot read asset image {image_path}: {e}"))?;
    let crc = crc32(&payload);
    let len = payload.len() as u32;
    eprintln!(
        "asset image: {image_path} ({len} bytes, crc32 0x{crc:08X})"
    );

    let port_path = match port {
        Some(p) => resolve_port(p)?,
        None => autodetect_port()?,
    };
    eprintln!("opening {port_path}");
    let mut sp = serialport::new(&port_path, BAUD)
        .timeout(Duration::from_millis(500))
        .open()
        .map_err(|e| format!("cannot open {port_path}: {e}"))?;

    // The firmware's TX/log path is gated on the CDC DTR line
    // (`Sender::wait_connection`); without DTR asserted, the device's PROV_*
    // status lines never reach us. Raise it, then give the device a moment to
    // notice the connection before we send the handshake.
    let _ = sp.write_data_terminal_ready(true);
    let _ = sp.write_request_to_send(true);
    std::thread::sleep(Duration::from_millis(100));

    // Handshake: magic + len + crc.
    let mut hs = Vec::with_capacity(HANDSHAKE.len() + 8);
    hs.extend_from_slice(HANDSHAKE);
    hs.extend_from_slice(&len.to_le_bytes());
    hs.extend_from_slice(&crc.to_le_bytes());
    sp.write_all(&hs).map_err(|e| format!("handshake write: {e}"))?;
    sp.flush().ok();

    eprintln!("waiting for erase…");
    if wait_for_any(&mut *sp, &["PROV_ERASED", "PROV_ERR"], Duration::from_secs(30))?
        == "PROV_ERR"
    {
        return Err("device reported PROV_ERR during erase".into());
    }

    eprintln!("streaming {len} bytes…");
    let mut written = 0usize;
    for chunk in payload.chunks(CHUNK) {
        sp.write_all(chunk).map_err(|e| format!("stream write: {e}"))?;
        written += chunk.len();
        if written % (CHUNK * 256) == 0 || written == payload.len() {
            eprint!("\r  {written}/{len}");
        }
    }
    sp.flush().ok();
    eprintln!();

    eprintln!("verifying…");
    let tok = wait_for_any(&mut *sp, &["PROV_OK", "PROV_ERR"], Duration::from_secs(30))?;
    if tok == "PROV_OK" {
        eprintln!("provisioned OK");
        Ok(())
    } else {
        Err("device reported PROV_ERR (crc mismatch or write error)".into())
    }
}

/// Read serial until a line containing any of `needles` arrives; returns the one
/// found. Device log lines are echoed to stderr (prefixed `  dev: `) as they
/// complete, so provisioning progress is visible.
fn wait_for_any(
    sp: &mut dyn serialport::SerialPort,
    needles: &[&str],
    timeout: Duration,
) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    let mut acc = String::new();
    let mut line = String::new();
    let mut buf = [0u8; 256];
    while Instant::now() < deadline {
        match sp.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                acc.push_str(&text);
                // Echo completed lines for visibility.
                for ch in text.chars() {
                    if ch == '\n' {
                        eprintln!("  dev: {}", line.trim_end());
                        line.clear();
                    } else {
                        line.push(ch);
                    }
                }
                for needle in needles {
                    if acc.contains(needle) {
                        if !line.is_empty() {
                            eprintln!("  dev: {}", line.trim_end());
                            line.clear();
                        }
                        return Ok((*needle).to_string());
                    }
                }
                // Bound memory: keep only the tail once it grows.
                if acc.len() > 4096 {
                    let tail = acc.len() - 512;
                    acc.drain(..tail);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("serial read: {e}")),
        }
    }
    Err(format!("timed out waiting for {needles:?}"))
}

/// Expand a glob-ish `/dev/tty.usbmodem*` to the first match, else return as-is.
fn resolve_port(p: &str) -> Result<String, String> {
    if p.contains('*') {
        first_glob(p).ok_or_else(|| format!("no serial port matches {p}"))
    } else {
        Ok(p.to_string())
    }
}

fn autodetect_port() -> Result<String, String> {
    let ports = serialport::available_ports().map_err(|e| format!("enumerate ports: {e}"))?;
    ports
        .into_iter()
        .map(|p| p.port_name)
        .find(|n| n.contains("usbmodem") || n.contains("ttyACM"))
        .ok_or_else(|| "no USB serial port found; pass --port".into())
}

fn first_glob(pat: &str) -> Option<String> {
    // Only support a trailing `*` on a directory prefix (e.g. /dev/tty.usbmodem*).
    let star = pat.find('*')?;
    let (prefix, _) = pat.split_at(star);
    let dir = std::path::Path::new(prefix).parent()?;
    let base = std::path::Path::new(prefix).file_name()?.to_str()?;
    let mut matches: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(base))
        .map(|n| dir.join(n).to_string_lossy().into_owned())
        .collect();
    matches.sort();
    matches.into_iter().next()
}
