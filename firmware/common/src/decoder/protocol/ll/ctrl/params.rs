//! Negotiated link parameters: timing, packet length, clock accuracy, subrating.
//!
//! Each of these is a request naming a range and a response naming what the peer
//! will accept, so both directions decode through the same arm. Together they
//! decide how often the link is on air and for how long, which is what a
//! follower's window has to match.

use core::fmt::Write;

use super::{line, send, u16le, write_interval, Decoder};

pub(super) struct Params;

impl Decoder<u8> for Params {
    fn keys(&self) -> &'static [u8] {
        &[0x0F, 0x10, 0x14, 0x15, 0x1D, 0x1E, 0x26, 0x27]
    }

    fn decode(&self, p: &[u8]) {
        let d = &p[1..];
        match p[0] {
            // LL_CONNECTION_PARAM_REQ / _RSP: Interval_Min Interval_Max Latency
            // Timeout PreferredPeriodicity ReferenceConnEventCount Offset0..5.
            //
            // ReferenceConnEventCount is the event the offsets are measured
            // from, in the peer's own numbering — so it is a free cross-check on
            // a follower's event counter, and the one field in an LL PDU that
            // can prove the counter has drifted away from the link.
            0x0F | 0x10 if d.len() >= 23 => {
                let mut s = line();
                let _ = s.push_str("interval=");
                write_interval(&mut s, u16le(d, 0));
                let _ = s.push_str("..");
                write_interval(&mut s, u16le(d, 2));
                let _ = write!(
                    s,
                    " latency={} timeout={}ms periodicity={} ref_ev={}",
                    u16le(d, 4), u16le(d, 6) as u32 * 10, d[8], u16le(d, 9)
                );
                send(s);
                let mut s = line();
                let _ = s.push_str("offsets=");
                for k in 0..6 {
                    if k > 0 {
                        let _ = s.push(',');
                    }
                    match u16le(d, 11 + k * 2) {
                        0xFFFF => {
                            let _ = s.push_str("none");
                        }
                        v => {
                            let _ = write!(s, "{}", v);
                        }
                    }
                }
                let _ = s.push_str(" (x1.25ms)");
                send(s);
            }
            // LL_LENGTH_REQ / _RSP: MaxRxOctets MaxRxTime MaxTxOctets MaxTxTime.
            // Each side states what it can receive and what it will transmit;
            // the link ends up using the smaller of the two in each direction.
            0x14 | 0x15 if d.len() >= 8 => {
                let mut s = line();
                let _ = write!(
                    s,
                    "rx={}B/{}us tx={}B/{}us",
                    u16le(d, 0), u16le(d, 2), u16le(d, 4), u16le(d, 6)
                );
                send(s);
            }
            // LL_CLOCK_ACCURACY_REQ / _RSP: the sender's current SCA.
            0x1D | 0x1E if !d.is_empty() => {
                let mut s = line();
                let _ = write!(s, "sca={} (<={}ppm)", d[0], Self::sca_ppm(d[0]));
                send(s);
            }
            // LL_SUBRATE_REQ: the factor range the sender wants.
            0x26 if d.len() >= 10 => {
                let mut s = line();
                let _ = write!(
                    s,
                    "subrate={}..{} max_latency={} continuation={} timeout={}ms",
                    u16le(d, 0), u16le(d, 2), u16le(d, 4), u16le(d, 6),
                    u16le(d, 8) as u32 * 10
                );
                send(s);
            }
            // LL_SUBRATE_IND: the factor actually applied, and the base event it
            // counts from — together these say which connection events the peers
            // will still use, so a follower listening on every event otherwise
            // sees the link go quiet with no procedure appearing to fail.
            0x27 if d.len() >= 10 => {
                let mut s = line();
                let _ = write!(
                    s,
                    "factor={} base_ev={} latency={} continuation={} timeout={}ms",
                    u16le(d, 0), u16le(d, 2), u16le(d, 4), u16le(d, 6),
                    u16le(d, 8) as u32 * 10
                );
                send(s);
            }
            _ => {}
        }
    }
}
/// The clock-accuracy table the `LL_CLOCK_ACCURACY_*` arms read.
impl Params {

    /// Sleep clock accuracy, as the worst-case ppm of the `SCA` field's range.
    ///
    /// The follower's own anchor error grows at the sum of both peers' accuracies,
    /// so the number that matters when a capture drifts is the upper bound, not the
    /// range: `sca=5` is "no worse than 50 ppm".
    fn sca_ppm(sca: u8) -> u16 {
        match sca & 7 {
            0 => 500,
            1 => 250,
            2 => 150,
            3 => 100,
            4 => 75,
            5 => 50,
            6 => 30,
            _ => 20,
        }
    }
}
