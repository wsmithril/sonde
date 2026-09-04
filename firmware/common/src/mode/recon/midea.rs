//! Midea control-channel probe: drive the C1→C2→C3 ECDH handshake over the live
//! GATT link, then send the 0xC0 status query and decode the reply with the
//! extended [`crate::device::midea::control`] decoder. This is the
//! connection-driving half of the Midea integration — the protocol state machine
//! (`Handshake`) and the status decode live in `crate::device::midea` (the single
//! source of truth); this file only moves frames over `crate::central`'s ATT
//! machinery and logs the decoded status.

use embassy_time::Instant;

use crate::central::{ATT_MTU_MAX, CONN_INTERVAL, Conn, att_write_await_notify};
use p256::elliptic_curve::rand_core::RngCore;

use crate::device::midea::{
    gatt::Profile,
    handshake::{Handshake, Recv},
    rng::HwRng,
};
use crate::{decoder, led};

use super::{HS_REPLY_EVENTS, SvFind, flash, sn_string};

/// C1 warm-up retries — the device drops the first frame, and midea-ble-go's
/// `pumpC1` resends up to 15× at its `C1Interval`. Give c1 the full budget.
const C1_RETRIES: u32 = 15;
/// c2/c3 retries — midea-ble-go's `pumpStep` resends the same frame up to 8×
/// (a fresh c2 would rotate the device's ephemeral key, so the frame is reused).
const STEP_RETRIES: u32 = 8;

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

/// Run the Midea control-channel handshake over the live link and return the
/// session state on success. Derives the rootKey from the advert (serial +
/// address), completes the ECDH session; all key material comes from the hardware
/// TRNG. Emits a detailed timing / packet trace for tuning.
pub(super) async fn probe(
    conn: &mut Conn,
    prof: &Profile,
    sn: &[u8; 14],
    addr: &[u8; 6],
    mac: Option<[u8; 6]>,
    st: &mut HsStats,
) -> HsOutcome {
    use crate::device::midea::crypto;

    // The rootKey's ikm is typeCode + SN8 + MAC6(reversed), where typeCode is
    // parsed from the serial (AC = 0xAC, ED = 0xED). midea-ble-go reads the MAC
    // from the advert's 0x06A8 payload, NOT the on-air address — a Midea device
    // randomising its address would otherwise derive a wrong rootKey and never
    // answer C1. Prefer the embedded MAC; fall back to the on-air address.
    let ad = match mac {
        Some(m) => crypto::advertis_data(sn, &m),
        None => crypto::advertis_data(sn, addr),
    };
    let Some(ad) = ad else {
        ulogf!(
            "  midea: invalid type code in serial {} — handshake skipped\r\n",
            sn_string(sn)
        );
        return HsOutcome::NoReply;
    };
    let mut rng = HwRng::new();
    // Client open-id: the reference sends 6 fresh random bytes every session
    // (midea-ble-go `randID6`) — zeros are tolerated but not what the app does.
    let mut open_id = [0u8; 6];
    rng.fill_bytes(&mut open_id);
    let mut hs = match Handshake::new(&ad, open_id, &mut rng) {
        Some(h) => h,
        None => return HsOutcome::NoReply,
    };
    let t_start = Instant::now();
    ulogf!(
        "  midea: state=c1 sn={} w={:04X} n={:04X} rootKey-derived (interval {}us, budget {} ev)\r\n",
        sn_string(sn),
        prof.write_h,
        prof.notify_h,
        CONN_INTERVAL as u32 * 1250,
        HS_REPLY_EVENTS
    );

    let mut out = [0u8; ATT_MTU_MAX];

    // c1: rebuilt each attempt (new seq/nonce), as the device ignores the first.
    let mut c1_len = None;
    for attempt in 1..=C1_RETRIES {
        let f = match hs.build_c1(&mut rng) {
            Some(f) => f,
            None => return HsOutcome::NoReply,
        };
        let t0 = Instant::now();
        st.writes += 1;
        if let Some(n) = att_write_await_notify(
            conn,
            prof.write_h,
            &f,
            prof.notify_h,
            HS_REPLY_EVENTS,
            &mut out,
        )
        .await
        {
            st.notifs += 1;
            flash(led::CYAN, 1); // peer answered this step
            ulogf!(
                "  midea[c1]: reply attempt={} in {}ms len={}\r\n",
                attempt,
                (Instant::now() - t0).as_millis(),
                n
            );
            c1_len = Some(n);
            break;
        }
        ulogf!(
            "  midea[c1]: attempt={} no reply after {}ms\r\n",
            attempt,
            (Instant::now() - t0).as_millis()
        );
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
        Some(Recv::C1(r)) => {
            if r == 1 {
                // midea-ble-go: a c1 result of 1 means the device already
                // recognizes us (session key cached from a prior bind) and wants
                // to skip c2/c3 into business. sonde does not cache session keys,
                // so we can't continue the reuse — log it and stop rather than
                // blindly walking into c2 on a key we don't have.
                ulogf!(
                    "  midea: c1 ack result=1 (device recognized) — session reuse not implemented, stopping\r\n"
                );
                return HsOutcome::SecError;
            }
            ulogf!("  midea: c1 ack result={}\r\n", r);
        }
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
    ulogf!(
        "  midea: sessionKey established (ECDH {}ms)\r\n",
        (Instant::now() - t_ecdh).as_millis()
    );

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
            r,
            (Instant::now() - t_start).as_millis(),
            st.writes,
            st.notifs
        ),
        Some(Recv::C3(r)) => {
            ulogf!("  midea: FAIL state=c3 (rejected result={})\r\n", r);
            return HsOutcome::NoReply;
        }
        _ => {
            ulogf!("  midea: FAIL state=c3 (unexpected reply)\r\n");
            return HsOutcome::NoReply;
        }
    }

    // Post-handshake: probe the appliance status. The query appliance frame is
    // type-specific (per the app's Lua templates): AC `build_query_frame`,
    // E2 `water_heater::build_query`; types without a defined query are skipped.
    // The reply (a sessionKey-encrypted C4 status frame) is decoded by the
    // matching per-appliance codec (`appliance::write_status`).
    // Sent via the same resend pattern as the handshake steps: the device drops
    // the first business frame (midea-ble-go `biz_interval`), so a single write
    // would always land in the void — the resend is the one the device answers.
    if let Some(ty) = crate::device::midea::appliance::Type::from_code(&sn[8..10])
        && let Some(query) = crate::device::midea::appliance::build_query(ty)
        && let Some(biz) = hs.build_biz(32, &query, &mut rng)
    {
        ulogf!("  midea: state=status-query\r\n");
        if let Some(n) = resend_await(conn, prof, &biz, &mut out, "status", st).await {
            st.status += 1;
            ulogf!("  midea[status]: reply len={}\r\n", n);
            decoder::hexdump(&out[..n], 0, 4);
            if let Some(Recv::Biz(body)) = hs.on_recv(&out[..n]) {
                // The decrypted business body — the raw appliance status frame
                // that the per-type codec decodes. Log it so a live capture
                // shows the exact bytes (the wire reply is sessionKey-encrypted).
                ulogf!("  midea[status]: decrypted len={}\r\n", body.len());
                decoder::hexdump(&body, 0, 6);
                let mut s: heapless::String<160> = heapless::String::new();
                if crate::device::midea::appliance::write_status(ty, &body, &mut s) {
                    ulogf!("  midea[status]: {}\r\n", s);
                } else {
                    ulogf!(
                        "  midea[status]: not a decodable {} status frame (len={})\r\n",
                        core::str::from_utf8(ty.code()).unwrap_or("?"),
                        body.len()
                    );
                }
            }
        } else {
            ulogf!("  midea[status]: no reply (device quiet)\r\n");
        }
    }
    HsOutcome::Complete(hs)
}

/// Fast FFA0 profile resolve: find the service by UUID, then **derive** the
/// control handles from the service start rather than discovering them. The
/// observed standard layout (5 handshakes, 2026-08-19 log) puts the FFA1 write
/// value at `start+2`, the FFA2 notify value at `start+5`, and its CCCD at
/// `start+6`. Subscribes the derived CCCD for notifications (the AC's FFA2 reply
/// channel is a notify — the reference controller subscribes 0x0001) — a wrong
/// CCCD handle fails the write, so a non-standard layout surfaces as
/// [`SvFind::NoChars`] and the caller falls back to full discovery.
///
/// Returns the full [`SvFind`] outcome — not just a profile — so the caller can
/// conclude on an absent/gated service without re-running the find (the ATT
/// error response *is* the existence signal; a second find on a service we know
/// is absent only costs a round trip on the marginal link).
pub(super) async fn resolve_ffa0_fast(conn: &mut Conn) -> SvFind {
    use crate::central::ServiceFind;

    match crate::central::find_service16(conn, 0xFFA0).await {
        ServiceFind::Found { start, .. } => {
            let write_h = start + 2;
            let notify_h = start + 5;
            // Best-effort CCCD subscribe: the reference controller
            // (`RemoteControllerDevice.indicate`) never writes the descriptor —
            // the appliance sends its FFA2 replies as notifications regardless —
            // and the handshake's write-and-listen path catches them either way.
            // A failed subscribe is therefore *not* a non-standard layout; report
            // Found so the handshake gets its chance. The caller re-resolves by
            // full discovery if the handshake then gets no reply.
            let _ = crate::central::subscribe(conn, notify_h + 1, 0x10).await;
            SvFind::Found(crate::device::midea::gatt::Profile { write_h, notify_h })
        }
        ServiceFind::Absent => SvFind::Absent,
        ServiceFind::Gated(code) => SvFind::Gated(code),
        ServiceFind::Unknown => SvFind::Unknown,
    }
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
    for attempt in 1..=STEP_RETRIES {
        let t0 = Instant::now();
        st.writes += 1;
        if let Some(n) = att_write_await_notify(
            conn,
            prof.write_h,
            frame,
            prof.notify_h,
            HS_REPLY_EVENTS,
            out,
        )
        .await
        {
            st.notifs += 1;
            flash(led::CYAN, 1); // peer answered this step
            ulogf!(
                "  midea[{}]: reply attempt={} in {}ms len={}\r\n",
                phase,
                attempt,
                (Instant::now() - t0).as_millis(),
                n
            );
            return Some(n);
        }
        ulogf!(
            "  midea[{}]: attempt={} no reply after {}ms\r\n",
            phase,
            attempt,
            (Instant::now() - t0).as_millis()
        );
    }
    None
}
