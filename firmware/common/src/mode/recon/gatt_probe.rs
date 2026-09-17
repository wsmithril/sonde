//! Device-agnostic, no-pairing GATT reconnaissance.
//!
//! This module owns the recon policy. `central` supplies only the connection,
//! ATT transaction, discovery, and CCCD primitives. UUIDs from
//! `gatt-services.md` label known service suggestions in the log; every
//! discovered characteristic is still tested according to its properties.

use core::fmt::Write;

use embassy_time::Instant;

use crate::central::{
    Characteristic, MAX_CHARS_PER_SVC, ProbeAttResult, ProbeAttStatus, Service, ServiceFind,
    char_props, discover_characteristics, discover_descriptors, find_service16,
    listen_notifications, probe_read_one, probe_subscribe, probe_write_command_empty,
    probe_write_request_empty,
};
use crate::decoder;

const DEVICE_NAME_UUID: u16 = 0x2A00;
const GAP_SERVICE_UUID: u16 = 0x1800;
const SHORT_NAME_MAX: usize = 32;

/// Result of one complete no-secret GATT pass.
#[derive(Default)]
pub(crate) struct Summary {
    pub(crate) services: u32,
    pub(crate) characteristics: u32,
    pub(crate) readable: u32,
    pub(crate) read_accepted: u32,
    pub(crate) read_errors: u32,
    pub(crate) writable: u32,
    pub(crate) write_accepted: u32,
    pub(crate) write_errors: u32,
    pub(crate) subscribable: u32,
    pub(crate) subscribe_accepted: u32,
    pub(crate) subscribe_errors: u32,
    pub(crate) notifications: u32,
}

/// Result of the cheap identity pass that runs before the full GATT walk.
pub(crate) enum NameProbe {
    Found(heapless::Vec<u8, SHORT_NAME_MAX>),
    Absent,
    Denied(u8),
    NoReply,
    Unexpected(u8),
}

/// Read the standard GAP Device Name before probing the rest of the database.
///
/// This is deliberately a targeted pass: the recon policy uses it to discard
/// known local devices before spending time on service enumeration and writes.
/// A peer that does not expose GAP/Device Name is left eligible for generic
/// reconnaissance.
pub(crate) async fn read_short_name(conn: &mut crate::central::Conn) -> NameProbe {
    let ServiceFind::Found { start, end } = find_service16(conn, GAP_SERVICE_UUID).await else {
        return NameProbe::Absent;
    };
    let service = Service {
        start,
        end,
        uuid: [0; 16],
        uuid_len: 0,
    };
    let mut chars: heapless::Vec<Characteristic, MAX_CHARS_PER_SVC> = heapless::Vec::new();
    discover_characteristics(conn, &service, &mut chars).await;
    let Some(name) = chars.iter().find(|ch| ch.uuid16 == Some(DEVICE_NAME_UUID)) else {
        return NameProbe::Absent;
    };
    let result = probe_read_one(conn, name.value_handle).await;
    match result.status {
        ProbeAttStatus::Accepted => {
            let mut value = heapless::Vec::new();
            let _ =
                value.extend_from_slice(&result.value[..result.value.len().min(SHORT_NAME_MAX)]);
            NameProbe::Found(value)
        }
        ProbeAttStatus::Error(code) => NameProbe::Denied(code),
        ProbeAttStatus::NoReply => NameProbe::NoReply,
        ProbeAttStatus::Unexpected(opcode) => NameProbe::Unexpected(opcode),
    }
}

fn log_gatt_item(svc: &Service, chars: Option<&Characteristic>) {
    let mut line = decoder::LogStr::new();
    match chars {
        Some(ch) => {
            let mut props = heapless::String::<48>::new();
            char_props(ch.props, &mut props);
            let _ = write!(
                line,
                "    - chr h={:04X} val={:04X} [{}] ",
                ch.decl_handle, ch.value_handle, props
            );
            decoder::gatt::write_uuid(&mut line, &ch.uuid[..ch.uuid_len as usize]);
        }
        None => {
            let _ = write!(line, "  - svc [{:04X}-{:04X}] ", svc.start, svc.end);
            decoder::gatt::write_uuid(&mut line, &svc.uuid[..svc.uuid_len as usize]);
        }
    }
    decoder::emit(line);
}

fn service_action(svc: &Service) -> &'static str {
    match crate::device::uuid16(&svc.uuid[..svc.uuid_len as usize]) {
        Some(0xFFA0) => "Midea: subscribe FFA2, empty-write FFA1",
        Some(0xFFF0) => "TCL scale: subscribe FFF1; listen for measurement",
        Some(0xF900) => "TCL soundbar: empty-write F901, subscribe/indicate F902",
        Some(0xF100) => "TCL softAP: enumerate and probe every characteristic",
        _ if svc.uuid_len == 16 && svc.uuid == nus_uuid(1) => {
            "Changhong NUS: subscribe 6E400003, empty-write 6E400002"
        }
        _ => "generic: probe properties advertised by each characteristic",
    }
}

fn nus_uuid(id: u8) -> [u8; 16] {
    [
        0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0, 0x93, 0xF3, 0xA3, 0xB5, id, 0x00, 0x40,
        0x6E,
    ]
}

fn log_read_value(uuid16: Option<u16>, value: &[u8], layout: &crate::decoder::gatt::HidLayout) {
    if let Some(uuid16) = uuid16
        && let Some((line, used)) = decoder::gatt::decode_hid_value(uuid16, value, layout)
    {
        decoder::emit(line);
        if used < value.len() {
            decoder::hexdump(&value[used..], used, 8);
        }
        return;
    }
    if value.is_empty() {
        ulog!("        value=<empty>\r\n");
    } else if value
        .iter()
        .all(|&byte| byte.is_ascii_graphic() || byte == b' ')
    {
        if let Ok(text) = core::str::from_utf8(value) {
            let mut line = decoder::LogStr::new();
            let _ = write!(line, "        value_ascii=\"{}\"\r\n", text);
            decoder::emit(line);
        } else {
            ulogf!("        value_hex len={}\r\n", value.len());
            decoder::hexdump(value, 0, 8);
        }
    } else {
        ulogf!("        value_hex len={}\r\n", value.len());
        decoder::hexdump(value, 0, 8);
    }
}

fn log_result(
    op: &str,
    handle: u16,
    uuid16: Option<u16>,
    result: &ProbeAttResult,
    layout: &crate::decoder::gatt::HidLayout,
    elapsed_ms: u64,
) -> bool {
    match result.status {
        ProbeAttStatus::Accepted => {
            ulogf!(
                "      {} h={:04X} result=accepted len={} elapsed={}ms\r\n",
                op,
                handle,
                result.value.len(),
                elapsed_ms
            );
            if matches!(op, "read" | "read_desc") {
                log_read_value(uuid16, &result.value, layout);
            }
            true
        }
        ProbeAttStatus::Error(code) => {
            ulogf!(
                "      {} h={:04X} result=denied err=0x{:02X} ({}) elapsed={}ms\r\n",
                op,
                handle,
                code,
                crate::central::att_error_name(code),
                elapsed_ms
            );
            false
        }
        ProbeAttStatus::NoReply => {
            ulogf!(
                "      {} h={:04X} result=no_reply elapsed={}ms\r\n",
                op,
                handle,
                elapsed_ms
            );
            false
        }
        ProbeAttStatus::Unexpected(opcode) => {
            ulogf!(
                "      {} h={:04X} result=unexpected_att=0x{:02X} elapsed={}ms\r\n",
                op,
                handle,
                opcode,
                elapsed_ms
            );
            false
        }
    }
}

/// Enumerate every discovered service and characteristic, then issue only
/// property-gated, minimal probes. CCCD writes happen before empty writes so a
/// write-triggered notification has a chance to be observed.
pub(crate) async fn run(conn: &mut crate::central::Conn, services: &[Service]) -> Summary {
    let mut out = Summary {
        services: services.len() as u32,
        ..Summary::default()
    };
    ulogf!(
        "  begin services={} pairing=off read=one-byte write=empty\r\n",
        services.len()
    );

    for svc in services {
        let service_start = Instant::now();
        log_gatt_item(svc, None);
        ulogf!("  suggested_action={}\r\n", service_action(svc));
        let mut chars: heapless::Vec<Characteristic, MAX_CHARS_PER_SVC> = heapless::Vec::new();
        discover_characteristics(conn, svc, &mut chars).await;
        ulogf!(
            "  service_chars range={:04X}-{:04X} count={} elapsed={}ms\r\n",
            svc.start,
            svc.end,
            chars.len(),
            Instant::now()
                .saturating_duration_since(service_start)
                .as_millis()
        );
        if chars.len() == MAX_CHARS_PER_SVC {
            ulogf!(
                "  characteristic_capacity_reached={} possible_truncation=true\r\n",
                MAX_CHARS_PER_SVC
            );
        }
        for ci in 0..chars.len() {
            let ch = chars[ci];
            out.characteristics += 1;
            conn.register_hid_report(&ch);
            log_gatt_item(svc, Some(&ch));

            if ch.props & 0x02 != 0 {
                out.readable += 1;
                let op_start = Instant::now();
                let result = probe_read_one(conn, ch.value_handle).await;
                if ch.uuid16 == Some(0x2A4B)
                    && let Some((_, _, layout)) = decoder::gatt::decode_report_map(&result.value)
                {
                    conn.set_hid_layout(layout);
                }
                if log_result(
                    "read",
                    ch.value_handle,
                    ch.uuid16,
                    &result,
                    conn.hid_layout(),
                    Instant::now()
                        .saturating_duration_since(op_start)
                        .as_millis(),
                ) {
                    out.read_accepted += 1;
                } else {
                    out.read_errors += 1;
                }
            }

            let desc_to = if ci + 1 < chars.len() {
                chars[ci + 1].decl_handle.saturating_sub(1)
            } else {
                svc.end
            };
            let descriptors = discover_descriptors(conn, ch.value_handle + 1, desc_to).await;

            if let Some(handle) = descriptors.user_description {
                let op_start = Instant::now();
                let result = probe_read_one(conn, handle).await;
                let _ = log_result(
                    "read_desc",
                    handle,
                    None,
                    &result,
                    conn.hid_layout(),
                    Instant::now()
                        .saturating_duration_since(op_start)
                        .as_millis(),
                );
            }

            if ch.props & 0x30 != 0 {
                out.subscribable += 1;
                match descriptors.cccd {
                    Some(h) => {
                        let op_start = Instant::now();
                        if probe_subscribe(conn, h, ch.props).await {
                            out.subscribe_accepted += 1;
                            ulogf!(
                                "      subscribe h={:04X} cccd={:04X} result=accepted elapsed={}ms\r\n",
                                ch.value_handle,
                                h,
                                Instant::now()
                                    .saturating_duration_since(op_start)
                                    .as_millis()
                            );
                        } else {
                            out.subscribe_errors += 1;
                            ulogf!(
                                "      subscribe h={:04X} cccd={:04X} result=denied elapsed={}ms\r\n",
                                ch.value_handle,
                                h,
                                Instant::now()
                                    .saturating_duration_since(op_start)
                                    .as_millis()
                            );
                        }
                    }
                    None => {
                        out.subscribe_errors += 1;
                        ulogf!(
                            "      subscribe h={:04X} result=no_cccd\r\n",
                            ch.value_handle
                        );
                    }
                }
            }

            if ch.props & 0x0C != 0 {
                out.writable += 1;
                let (op, result) = if ch.props & 0x08 != 0 {
                    let op_start = Instant::now();
                    (
                        "write_req",
                        (
                            probe_write_request_empty(conn, ch.value_handle).await,
                            op_start,
                        ),
                    )
                } else {
                    let op_start = Instant::now();
                    (
                        "write_cmd_link_ack",
                        (
                            probe_write_command_empty(conn, ch.value_handle).await,
                            op_start,
                        ),
                    )
                };
                if log_result(
                    op,
                    ch.value_handle,
                    ch.uuid16,
                    &result.0,
                    conn.hid_layout(),
                    Instant::now()
                        .saturating_duration_since(result.1)
                        .as_millis(),
                ) {
                    out.write_accepted += 1;
                } else {
                    out.write_errors += 1;
                }
            }
        }
    }

    // Keep the link alive after all CCCDs and empty writes. This catches delayed
    // notifications and logs their characteristic handles and payloads.
    let listen_start = Instant::now();
    out.notifications = listen_notifications(conn, crate::central::LISTEN_EVENTS).await;
    ulogf!(
        "  done services={} chars={} read={}/{} write={}/{} subscribe={}/{} notifications={} listen_elapsed={}ms\r\n",
        out.services,
        out.characteristics,
        out.read_accepted,
        out.readable,
        out.write_accepted,
        out.writable,
        out.subscribe_accepted,
        out.subscribable,
        out.notifications,
        Instant::now()
            .saturating_duration_since(listen_start)
            .as_millis()
    );
    out
}
