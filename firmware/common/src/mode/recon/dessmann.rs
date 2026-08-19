//! DESSMANN smart-lock probe: enumerate the safe commands on a lock and — when
//! it answers the cipher-capability challenge — the state-changing surface
//! (inert without the sekey-derived MAC). The framing and command set come from
//! [`crate::device::dessmann`]; this driver only moves frames over ATT.

use crate::central::{ATT_MTU_MAX, Conn, att_write_await_notify};
use crate::device::dessmann::{self, Cmd, Profile, build_cmd};
use crate::decoder;

use super::HS_REPLY_EVENTS;

/// Probe a DESSMANN lock: challenge → safe commands → (cipher-capable only)
/// state-changing commands. Every raw reply is hex-dumped so the SDK-derived
/// framing can be confirmed or corrected on a live lock.
pub(super) async fn probe(conn: &mut Conn, prof: &Profile) {
    let mut out = [0u8; ATT_MTU_MAX];

    // Cipher-capability: an 8-byte challenge reply means the open path is
    // MAC-protected, so the state-changing commands below cannot succeed. Probe
    // the challenge first — its reply length decides the rest.
    let mut cipher = false;
    let frame = build_cmd(Cmd::GetChallenge, &[]);
    ulogf!("  dessmann: {} (0x{:02X})\r\n", Cmd::GetChallenge.name(), Cmd::GetChallenge.byte());
    if let Some(n) =
        att_write_await_notify(conn, prof.write_h, &frame, prof.notify_h, HS_REPLY_EVENTS, &mut out).await
    {
        ulogf!("    reply len={}\r\n", n);
        decoder::hexdump(&out[..n], 0, 4);
        // A framed 8-byte challenge payload would be 14 bytes (FE 01 rsp 00 08
        // <8 bytes> <chk2>). Anything that long is treated as cipher-capable.
        cipher = n >= 14;
    } else {
        ulogf!("    no reply\r\n");
    }

    // Safe reads — always sent, never change state.
    for cmd in Cmd::SAFE {
        if cmd == Cmd::GetChallenge {
            continue; // already probed
        }
        let frame = build_cmd(cmd, &[]);
        ulogf!("  dessmann: {} (0x{:02X})\r\n", cmd.name(), cmd.byte());
        if let Some(n) =
            att_write_await_notify(conn, prof.write_h, &frame, prof.notify_h, HS_REPLY_EVENTS, &mut out).await
        {
            ulogf!("    reply len={}\r\n", n);
            decoder::hexdump(&out[..n], 0, 4);
        } else {
            ulogf!("    no reply\r\n");
        }
    }

    // State-changing commands: only on a cipher-capable lock (they need the MAC
    // and will error, mapping the response surface), and only when enabled.
    if cipher && dessmann::PROBE_MUTATING {
        ulogf!("  dessmann: cipher-capable — probing state-changing commands (inert without sekey MAC)\r\n");
        for cmd in Cmd::MUTATING {
            let frame = build_cmd(cmd, &[]);
            ulogf!("  dessmann: {} (0x{:02X})\r\n", cmd.name(), cmd.byte());
            if let Some(n) =
                att_write_await_notify(conn, prof.write_h, &frame, prof.notify_h, HS_REPLY_EVENTS, &mut out).await
            {
                ulogf!("    reply len={}\r\n", n);
                decoder::hexdump(&out[..n], 0, 4);
            } else {
                ulogf!("    no reply\r\n");
            }
        }
    } else if !cipher {
        ulogf!("  dessmann: not cipher-capable — state-changing commands skipped\r\n");
    }
}
