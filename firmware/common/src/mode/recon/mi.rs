//! Mi device probes: the body-composition-scale weigh-in listen and the
//! MiBeacon-sensor GATT walk. Detection (`is_sensor_advert` / `is_scale_advert`)
//! and the measurement decode live in [`crate::device::mi`]; these drivers only
//! hold the link and wait for the notification.

use embassy_time::{Duration, Instant};

use crate::central::{
    ATT_HANDLE_VALUE_IND, ATT_HANDLE_VALUE_NTF, Conn, LISTEN_EVENTS, MAX_CONSEC_MISS,
    RX_BUF, Reasm, Service, conn_event, listen_notifications, stage_empty, update_flow,
    walk_services,
};
use crate::device::mi;
use crate::decoder;

/// Mi Body Composition Scale probe: hold the link with the measurement channel
/// subscribed and wait for a weigh-in — the scale only pushes a 13-byte
/// measurement (weight + impedance + timestamp) when someone stands on it.
/// Decode and log any measurement seen during the window.
pub(super) async fn probe_scale(conn: &mut Conn, prof: &mi::Profile) {
    let mut asm = Reasm::new();
    let mut miss = 0u32;
    let mut got = 0u32;
    let deadline = Instant::now() + Duration::from_secs(60);
    ulogf!("  miscale: awaiting a weigh-in on h={:04X} (60 s)\r\n", prof.notify_h);
    while Instant::now() < deadline {
        let Some(rx) = conn_event(conn, stage_empty(conn)).await else {
            miss += 1;
            if miss >= MAX_CONSEC_MISS {
                break;
            }
            continue;
        };
        miss = 0;
        let (new_data, _) = update_flow(conn, &rx);
        if !new_data || rx.len == 0 {
            continue;
        }
        let buf = unsafe { &*RX_BUF.0.get() };
        let payload = &buf[2..2 + rx.len as usize];
        if !asm.push(rx.llid, payload) {
            continue;
        }
        if asm.cid == 0x0004 {
            let frame = asm.frame();
            if frame.len() >= 3
                && matches!(frame[0], ATT_HANDLE_VALUE_NTF | ATT_HANDLE_VALUE_IND)
                && u16::from_le_bytes([frame[1], frame[2]]) == prof.notify_h
            {
                let val = &frame[3..];
                match mi::parse_measurement(val) {
                    Some(m) => {
                        ulogf!(
                            "  miscale: WEIGH-IN {} {:04}-{:02}-{:02} {:02}:{:02}:{:02} weight={:.2} kg impedance={} {}\r\n",
                            if m.lbs { "(lbs)" } else { "(kg)" },
                            m.year, m.month, m.day, m.hour, m.minute, m.second,
                            m.weight_kg(), m.impedance,
                            if m.has_impedance { "(composition possible)" } else { "(no impedance)" }
                        );
                        got += 1;
                    }
                    None => {
                        ulogf!("  miscale: notification h={:04X} len={} (not a measurement)\r\n",
                            prof.notify_h, val.len());
                        decoder::hexdump(val, 0, 4);
                    }
                }
                if got >= 4 {
                    break;
                }
            }
        }
        asm.clear();
    }
    if got == 0 {
        ulogf!("  miscale: no weigh-in during the window\r\n");
    }
}

/// MiBeacon sensor (XMZNMS08LM door/window, LYWSD03MMC temp/humidity): no
/// control profile, but the GATT walk reads its sensor values (temperature,
/// humidity, battery on the stock LYWSD03MMC). Walk the services and, when any
/// characteristic subscribed, listen for notifications. Returns the subscribe
/// count so the caller can report it.
pub(super) async fn probe_sensor(conn: &mut Conn, services: &[Service]) -> u32 {
    let subscribed = walk_services(conn, services, |_vh, _uuid| {}).await;
    if subscribed > 0 {
        listen_notifications(conn, LISTEN_EVENTS).await;
    }
    subscribed
}
