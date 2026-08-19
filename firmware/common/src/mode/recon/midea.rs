//! Midea control-channel probe: drive the C1→C2→C3 ECDH handshake over the live
//! GATT link, then send the 0xC0 status query and decode the reply with the
//! extended [`crate::device::midea::control`] decoder. This is the
//! connection-driving half of the Midea integration — the protocol state machine
//! (`Handshake`) and the status decode live in `crate::device::midea` (the single
//! source of truth); this file only moves frames over `crate::central`'s ATT
//! machinery and logs the decoded status.

use embassy_time::Instant;

use crate::central::{ATT_MTU_MAX, CONN_INTERVAL, Conn, att_write_await_notify};
use crate::device::midea::{
    control,
    gatt::Profile,
    handshake::{Handshake, Recv},
    rng::HwRng,
};
use crate::{decoder, led};

use super::{flash, sn_string, HS_REPLY_EVENTS};

/// How many times to resend a step whose reply never arrives (the appliance
/// drops the first frame of each step — midea-ble-go `session.go`).
const HS_RETRIES: u32 = 4;

/// Running counters for the per-device summary line.
#[derive(Default)]
pub(super) struct HsStats {
    pub(super) writes: u32, // ATT writes we sent (handshake frames)
    pub(super) notifs: u32, // notifications received on FFA2
    pub(super) status: u32, // decrypted 0xC0 status frames
}

/// Handshake outcome, distinguished by why it aborted so the picker can choose
/// the right cooldown: a device that *answered* with a security error is treated
/// as an unsupported control type and cooled for far longer than a plain
/// no-reply.
pub(super) enum HsOutcome {
    Complete(Handshake),
    /// The device rejected our frames with an ff04/ff05 security error (or sent
    /// a frame that does not parse as the expected step) — unsupported type.
    SecError,
    /// The device never answered — retry on the normal cadence.
    NoReply,
}

/// Log the decoded 0xC0 AC status reply — the extended fields (power / mode /
/// target / fan plus indoor/outdoor temp, eco/turbo/elec-heat, screen, error).
fn log_status(f: &[u8]) {
    match control::parse_status_frame(f) {
        Some(st) => {
            let mut s: heapless::String<160> = heapless::String::new();
            if st.fmt_to(&mut s).is_ok() {
                ulogf!("  midea[status]: {}\r\n", s);
            }
        }
        None => ulogf!("  midea[status]: not a decodable 0xC0 status frame (len={})\r\n", f.len()),
    }
}

/// Run the Midea control-channel handshake over the live link and return the
/// session state on success. Derives the rootKey from the advert (serial +
/// address), completes the ECDH session; all key material comes from the hardware
/// TRNG. Emits a detailed timing / packet trace for tuning.
pub(super) async fn probe(
    conn: &mut Conn,
    prof: &Profile,
    sn: &[u8; 14],
    addr: &[u8; 6],
    st: &mut HsStats,
) -> HsOutcome {
    use crate::device::midea::crypto;

    let ad = crypto::advertis_data(sn, addr);
    let mut rng = HwRng::new();
    // Client open-id: a 6-byte identifier the app would supply; zeros work here.
    let mut hs = match Handshake::new(&ad, [0u8; 6], &mut rng) {
        Some(h) => h,
        None => return HsOutcome::NoReply,
    };
    let t_start = Instant::now();
    ulogf!("  midea: state=c1 sn={} w={:04X} n={:04X} rootKey-derived (interval {}us, budget {} ev)\r\n",
        sn_string(sn), prof.write_h, prof.notify_h, CONN_INTERVAL as u32 * 1250, HS_REPLY_EVENTS);

    let mut out = [0u8; ATT_MTU_MAX];

    // c1: rebuilt each attempt (new seq/nonce), as the device ignores the first.
    let mut c1_len = None;
    for attempt in 1..=HS_RETRIES {
        let f = match hs.build_c1(&mut rng) {
            Some(f) => f,
            None => return HsOutcome::NoReply,
        };
        let t0 = Instant::now();
        st.writes += 1;
        if let Some(n) =
            att_write_await_notify(conn, prof.write_h, &f, prof.notify_h, HS_REPLY_EVENTS, &mut out).await
        {
            st.notifs += 1;
            flash(led::CYAN, 1); // peer answered this step
            ulogf!("  midea[c1]: reply attempt={} in {}ms len={}\r\n",
                attempt, (Instant::now() - t0).as_millis(), n);
            c1_len = Some(n);
            break;
        }
        ulogf!("  midea[c1]: attempt={} no reply after {}ms\r\n",
            attempt, (Instant::now() - t0).as_millis());
    }
    // Gate c2 on a recognised c1 ack: a security error (ff04) or an unparseable
    // reply means the device rejected the handshake — sending c2 anyway only
    // wastes two more round trips on a device that will never validate us.
    let n = match c1_len {
        Some(n) => n,
        None => {
            ulogf!("  midea: FAIL state=c1 (no reply)\r\n");
            return HsOutcome::NoReply;
        }
    };
    match hs.on_recv(&out[..n]) {
        Some(Recv::C1(r)) => ulogf!("  midea: c1 ack result={}\r\n", r),
        _ => {
            ulogf!("  midea: c1 reply not an ack (security error / unparseable) — unsupported\r\n");
            return HsOutcome::SecError;
        }
    }

    // c2: same frame on retry (a fresh c2 rotates the device's ephemeral key).
    ulogf!("  midea: state=c2\r\n");
    let c2 = match hs.build_c2(&mut rng) {
        Some(f) => f,
        None => return HsOutcome::NoReply,
    };
    let n = match resend_await(conn, prof, &c2, &mut out, "c2", st).await {
        Some(n) => n,
        None => {
            ulogf!("  midea: FAIL state=c2 (no reply)\r\n");
            return HsOutcome::NoReply;
        }
    };
    let peer = match hs.on_recv(&out[..n]) {
        Some(Recv::C2(p)) => p,
        _ => {
            ulogf!("  midea: c2 reply not a public key (security error) — unsupported\r\n");
            return HsOutcome::SecError;
        }
    };
    let t_ecdh = Instant::now();
    if hs.complete_c2(&peer, &mut rng).is_none() {
        ulogf!("  midea: FAIL state=c2 (ECDH/session derivation)\r\n");
        return HsOutcome::NoReply;
    }
    ulogf!("  midea: sessionKey established (ECDH {}ms)\r\n", (Instant::now() - t_ecdh).as_millis());

    // c3: our public key + sessionKey-encrypted advertisData, rootKey-wrapped.
    ulogf!("  midea: state=c3\r\n");
    let c3 = match hs.build_c3(&mut rng) {
        Some(f) => f,
        None => return HsOutcome::NoReply,
    };
    let n = match resend_await(conn, prof, &c3, &mut out, "c3", st).await {
        Some(n) => n,
        None => {
            ulogf!("  midea: FAIL state=c3 (no reply)\r\n");
            return HsOutcome::NoReply;
        }
    };
    match hs.on_recv(&out[..n]) {
        Some(Recv::C3(r)) if r != 0 => ulogf!(
            "  midea: handshake complete (c3 result={}, {}ms total, tx={} rx={})\r\n",
            r, (Instant::now() - t_start).as_millis(), st.writes, st.notifs),
        Some(Recv::C3(r)) => {
            ulogf!("  midea: FAIL state=c3 (rejected result={})\r\n", r);
            return HsOutcome::NoReply;
        }
        _ => {
            ulogf!("  midea: FAIL state=c3 (unexpected reply)\r\n");
            return HsOutcome::NoReply;
        }
    }

    // Post-handshake: probe the appliance status, following midea-ble-go — it
    // sends a 0xC0 business query right after c3. The reply (a sessionKey-encrypted
    // C4 status frame) is decoded below with the extended status decoder.
    let query = control::build_query_frame(1, 0); // order=1, sound off — the reference golden
    if let Some(biz) = hs.build_biz(32, &query, &mut rng) {
        ulogf!("  midea: state=status-query\r\n");
        if let Some(n) =
            att_write_await_notify(conn, prof.write_h, &biz, prof.notify_h, HS_REPLY_EVENTS, &mut out).await
        {
            st.notifs += 1;
            st.status += 1;
            ulogf!("  midea[status]: reply len={}\r\n", n);
            decoder::hexdump(&out[..n], 0, 4);
            if let Some(Recv::Biz(body)) = hs.on_recv(&out[..n]) {
                log_status(&body);
            }
        } else {
            ulogf!("  midea[status]: no reply (device quiet)\r\n");
        }
    }
    HsOutcome::Complete(hs)
}

/// Resend one already-built handshake frame up to [`HS_RETRIES`] times, awaiting a
/// reply notification each time; logs attempt/latency and counts packets.
async fn resend_await(
    conn: &mut Conn,
    prof: &Profile,
    frame: &[u8],
    out: &mut [u8],
    phase: &str,
    st: &mut HsStats,
) -> Option<usize> {
    for attempt in 1..=HS_RETRIES {
        let t0 = Instant::now();
        st.writes += 1;
        if let Some(n) =
            att_write_await_notify(conn, prof.write_h, frame, prof.notify_h, HS_REPLY_EVENTS, out).await
        {
            st.notifs += 1;
            flash(led::CYAN, 1); // peer answered this step
            ulogf!("  midea[{}]: reply attempt={} in {}ms len={}\r\n",
                phase, attempt, (Instant::now() - t0).as_millis(), n);
            return Some(n);
        }
        ulogf!("  midea[{}]: attempt={} no reply after {}ms\r\n",
            phase, attempt, (Instant::now() - t0).as_millis());
    }
    None
}
