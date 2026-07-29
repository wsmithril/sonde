//! The procedures that move the link itself: when events happen and which
//! channels they happen on.
//!
//! These are the PDUs a follower must act on rather than merely print. Both
//! `LL_CONNECTION_UPDATE_IND` and `LL_CHANNEL_MAP_IND` carry an `Instant` — the
//! connection event counter value at which the new parameters take effect — so
//! the fields printed here are what a capture that desyncs at that event should
//! be read against.

use core::fmt::Write;

use super::{line, send, u16le, write_interval, write_phys, Decoder};

pub(super) struct Timeline;

impl Decoder<u8> for Timeline {
    fn keys(&self) -> &'static [u8] {
        &[0x00, 0x01, 0x19, 0x28, 0x29]
    }

    fn decode(&self, p: &[u8]) {
        let d = &p[1..];
        match p[0] {
            // LL_CONNECTION_UPDATE_IND: WinSize WinOffset Interval Latency
            // Timeout Instant.
            //
            // WinOffset is the field that moves the anchor. The first event at
            // the instant starts one transmit-window delay (1.25 ms) plus
            // WinOffset × 1.25 ms after the previous anchor, so a non-zero
            // WinOffset shifts the whole timeline forward on top of the new
            // interval — which is why it prints next to the interval it arrives
            // with rather than being folded into the window size.
            0x00 if d.len() >= 11 => {
                let mut s = line();
                let _ = s.push_str("interval=");
                write_interval(&mut s, u16le(d, 3));
                let _ = write!(s, " latency={} timeout={}ms", u16le(d, 5), u16le(d, 7) as u32 * 10);
                let _ = s.push_str(" winsize=");
                write_interval(&mut s, d[0] as u16);
                let _ = s.push_str(" winoffset=");
                write_interval(&mut s, u16le(d, 1));
                let _ = write!(s, " instant={}", u16le(d, 9));
                send(s);
            }
            // LL_CHANNEL_MAP_IND: ChM(5) Instant(2). The channel count is what
            // decides how often two event indices land on the same channel, so a
            // capture that keeps hitting on a small map is not evidence the hop
            // sequence is right.
            0x01 if d.len() >= 7 => {
                let mut s = line();
                let _ = write!(
                    s,
                    "chmap={:02X}{:02X}{:02X}{:02X}{:02X} ({} ch) instant={}",
                    d[0], d[1], d[2], d[3], d[4],
                    d[..5].iter().map(|b| b.count_ones()).sum::<u32>(),
                    u16le(d, 5)
                );
                send(s);
            }
            // LL_MIN_USED_CHANNELS_IND: PHYS(1) MinUsedChannels(1) — the
            // peripheral asking the central to keep at least this many channels
            // in the map.
            0x19 if d.len() >= 2 => {
                let mut s = line();
                let _ = s.push_str("phys=");
                write_phys(&mut s, d[0]);
                let _ = write!(s, " min_used_channels={}", d[1]);
                send(s);
            }
            // LL_CHANNEL_REPORTING_IND: Enable(1) MinSpacing(1) MaxDelay(1), the
            // last two in 200 ms units.
            0x28 if d.len() >= 3 => {
                let mut s = line();
                let _ = write!(
                    s,
                    "enable={} min_spacing={}ms max_delay={}ms",
                    d[0], d[1] as u32 * 200, d[2] as u32 * 200
                );
                send(s);
            }
            // LL_CHANNEL_STATUS_IND: a 10-octet classification bitmap, two bits
            // per data channel, sent by a peripheral that has been asked to
            // report what it hears.
            0x29 if d.len() >= 10 => {
                let mut s = line();
                let _ = s.push_str("classification=");
                for b in &d[..10] {
                    let _ = write!(s, "{:02X}", b);
                }
                send(s);
            }
            _ => {}
        }
    }
}
