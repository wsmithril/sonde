//! How procedures and links end: termination, rejection, unknown opcodes.
//!
//! These four PDUs all answer "why did that stop", and each names the thing it
//! is answering about. `LL_REJECT_EXT_IND` repeats the rejected opcode where
//! plain `LL_REJECT_IND` leaves it ambiguous on a link running several
//! procedures at once, and `LL_UNKNOWN_RSP` is how a peer says an opcode is
//! newer than its controller.

use core::fmt::Write;

use super::{ctrl_name, error_name, line, send, Decoder};

pub(super) struct Procedure;

impl Decoder<u8> for Procedure {
    fn keys(&self) -> &'static [u8] {
        &[0x02, 0x07, 0x0D, 0x11]
    }

    fn decode(&self, p: &[u8]) {
        let d = &p[1..];
        match p[0] {
            // LL_TERMINATE_IND / LL_REJECT_IND: a single error code.
            0x02 | 0x0D if !d.is_empty() => {
                let mut s = line();
                let _ = write!(s, "error=0x{:02X} ({})", d[0], error_name(d[0]));
                send(s);
            }
            // LL_UNKNOWN_RSP: the opcode the peer did not recognise.
            0x07 if !d.is_empty() => {
                let mut s = line();
                let _ = write!(s, "unknown_type=0x{:02X} ({})", d[0], ctrl_name(d[0]));
                send(s);
            }
            // LL_REJECT_EXT_IND: the rejected opcode plus the reason.
            0x11 if d.len() >= 2 => {
                let mut s = line();
                let _ = write!(
                    s,
                    "rejected=0x{:02X} ({}) error=0x{:02X} ({})",
                    d[0], ctrl_name(d[0]), d[1], error_name(d[1])
                );
                send(s);
            }
            _ => {}
        }
    }
}
