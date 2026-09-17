//! Small, allocation-free HID-over-GATT decoders.
//!
//! The report map is a bytecode descriptor rather than an application protocol.
//! This decoder extracts the application usage and the common mouse fields so a
//! recon log can say what the peer exposes while retaining the raw value for
//! descriptors it does not understand.

use core::fmt::Write;

use crate::decoder::LogStr;

#[derive(Clone, Copy, Default)]
pub(crate) struct HidLayout {
    pub(crate) valid: bool,
    pub(crate) application_page: u16,
    pub(crate) application_usage: u16,
    pub(crate) has_report_id: bool,
    pub(crate) report_id: u8,
    pub(crate) input_bits: u16,
    pub(crate) buttons: u8,
    pub(crate) button_offset: u16,
    pub(crate) x_bits: u8,
    pub(crate) x_offset: u16,
    pub(crate) x_relative: bool,
    pub(crate) y_bits: u8,
    pub(crate) y_offset: u16,
    pub(crate) y_relative: bool,
    pub(crate) wheel_bits: u8,
    pub(crate) wheel_offset: u16,
    pub(crate) wheel_relative: bool,
}

fn item_size(prefix: u8) -> usize {
    match prefix & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    }
}

fn item_value(data: &[u8]) -> u32 {
    let mut value = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        value |= (byte as u32) << (i * 8);
    }
    value
}

fn local_usage(
    layout: &mut HidLayout,
    page: u16,
    usage: u16,
    usages: &mut [u16; 8],
    count: &mut usize,
) {
    if *count < usages.len() {
        usages[*count] = usage;
        *count += 1;
    }
    if layout.application_page == 0 {
        layout.application_page = page;
    }
}

/// Parse a HID Report Map into the fields needed to describe and decode it.
/// `None` means that the descriptor is truncated or contains no Input item.
pub(crate) fn parse_report_map(value: &[u8]) -> Option<HidLayout> {
    let mut layout = HidLayout::default();
    let mut usage_page = 0u16;
    let mut usages = [0u16; 8];
    let mut usage_count = 0usize;
    let mut usage_min = 0u16;
    let mut usage_max = 0u16;
    let mut have_usage_range = false;
    let mut report_size = 0u8;
    let mut report_count = 0u8;
    let mut input_bits = 0u16;
    let mut depth = 0u8;
    let mut pos = 0usize;

    while pos < value.len() {
        let prefix = value[pos];
        pos += 1;
        if prefix == 0xFE {
            if pos + 2 > value.len() {
                return None;
            }
            let len = value[pos] as usize;
            pos += 2;
            if pos + len > value.len() {
                return None;
            }
            pos += len;
            continue;
        }
        let size = item_size(prefix);
        if pos + size > value.len() {
            return None;
        }
        let kind = (prefix >> 2) & 0x03;
        let tag = prefix >> 4;
        let raw = item_value(&value[pos..pos + size]);
        pos += size;

        match kind {
            // Main items.
            0 => match tag {
                0x08 => {
                    let bits = (report_size as u16).saturating_mul(report_count as u16);
                    let offset = input_bits;
                    input_bits = input_bits.saturating_add(bits);
                    let flags = raw as u8;
                    if usage_page == 0x09 {
                        let n = if have_usage_range {
                            usage_max.saturating_sub(usage_min).saturating_add(1)
                        } else {
                            report_count as u16
                        };
                        if n <= u8::MAX as u16 {
                            layout.buttons = n as u8;
                            layout.button_offset = offset;
                        }
                    }
                    for &usage in &usages[..usage_count] {
                        match (usage_page, usage) {
                            (0x01, 0x30) => {
                                layout.x_bits = report_size;
                                layout.x_offset = offset;
                                layout.x_relative = flags & 0x04 != 0;
                            }
                            (0x01, 0x31) => {
                                layout.y_bits = report_size;
                                layout.y_offset = offset;
                                layout.y_relative = flags & 0x04 != 0;
                            }
                            (0x01, 0x38) => {
                                layout.wheel_bits = report_size;
                                layout.wheel_offset = offset;
                                layout.wheel_relative = flags & 0x04 != 0;
                            }
                            _ => {}
                        }
                    }
                    usage_count = 0;
                    have_usage_range = false;
                }
                0x0A => {
                    depth = depth.saturating_add(1);
                    if depth == 1 {
                        layout.application_page = usage_page;
                        layout.application_usage = usages.first().copied().unwrap_or(0);
                    }
                    usage_count = 0;
                    have_usage_range = false;
                }
                0x0C => {
                    depth = depth.saturating_sub(1);
                    usage_count = 0;
                    have_usage_range = false;
                }
                _ => {
                    usage_count = 0;
                    have_usage_range = false;
                }
            },
            // Global items.
            1 => match tag {
                0x00 => usage_page = raw as u16,
                0x07 => report_size = raw as u8,
                0x08 => {
                    layout.has_report_id = true;
                    layout.report_id = raw as u8;
                }
                0x09 => report_count = raw as u8,
                _ => {}
            },
            // Local items.
            2 => match tag {
                0x00 => local_usage(
                    &mut layout,
                    usage_page,
                    raw as u16,
                    &mut usages,
                    &mut usage_count,
                ),
                0x01 => {
                    usage_min = raw as u16;
                    have_usage_range = true;
                }
                0x02 => {
                    usage_max = raw as u16;
                    have_usage_range = true;
                }
                _ => {}
            },
            _ => {}
        }
    }

    layout.input_bits = input_bits;
    layout.valid = input_bits != 0;
    layout.valid.then_some(layout)
}

fn application_name(page: u16, usage: u16) -> &'static str {
    match (page, usage) {
        (0x01, 0x02) => "mouse",
        (0x01, 0x06) => "keyboard",
        (0x01, 0x04) => "joystick",
        (0x01, 0x05) => "gamepad",
        _ => "other",
    }
}

fn write_axis(s: &mut LogStr, name: &str, bits: u8, relative: bool) {
    let _ = write!(
        s,
        " {}={}bit/{}",
        name,
        bits,
        if relative { "relative" } else { "absolute" }
    );
}

/// Render the useful portion of a Report Map as one line.
pub(crate) fn decode_report_map(value: &[u8]) -> Option<(LogStr, usize, HidLayout)> {
    let layout = parse_report_map(value)?;
    let mut line = LogStr::new();
    let _ = write!(
        line,
        "        hid_report_map len={} application={} report_id={} input_bytes={}",
        value.len(),
        application_name(layout.application_page, layout.application_usage),
        if layout.has_report_id {
            layout.report_id
        } else {
            0
        },
        (layout.input_bits as usize).div_ceil(8) + usize::from(layout.has_report_id)
    );
    if layout.application_page != 0 {
        let _ = write!(
            line,
            " usage=0x{:02X}:0x{:02X}",
            layout.application_page, layout.application_usage
        );
    }
    if layout.buttons != 0 {
        let _ = write!(line, " buttons={}", layout.buttons);
    }
    if layout.x_bits != 0 {
        write_axis(&mut line, "x", layout.x_bits, layout.x_relative);
    }
    if layout.y_bits != 0 {
        write_axis(&mut line, "y", layout.y_bits, layout.y_relative);
    }
    if layout.wheel_bits != 0 {
        write_axis(&mut line, "wheel", layout.wheel_bits, layout.wheel_relative);
    }
    Some((line, value.len(), layout))
}

fn bits(value: &[u8], offset: u16, width: u8) -> u32 {
    let mut result = 0u32;
    for bit in 0..width.min(32) {
        let absolute = offset as usize + bit as usize;
        let byte = absolute / 8;
        if byte < value.len() && value[byte] & (1 << (absolute % 8)) != 0 {
            result |= 1 << bit;
        }
    }
    result
}

fn signed(raw: u32, width: u8) -> i32 {
    if width == 0 || width >= 32 || raw & (1 << (width - 1)) == 0 {
        return raw as i32;
    }
    (raw | (!0u32 << width)) as i32
}

/// Decode one mouse-like HID input report using the previously parsed map.
pub(crate) fn decode_input_report(value: &[u8], layout: &HidLayout) -> Option<LogStr> {
    if !layout.valid || layout.application_page != 0x01 || layout.application_usage != 0x02 {
        return None;
    }
    let offset = usize::from(layout.has_report_id);
    if layout.has_report_id && value.first().copied()? != layout.report_id {
        return None;
    }
    let needed = (layout.input_bits as usize).div_ceil(8);
    if value.len() < offset + needed {
        return None;
    }
    let payload = &value[offset..];
    let button = bits(payload, layout.button_offset, 8.min(layout.buttons));
    let x = (layout.x_bits != 0)
        .then(|| signed(bits(payload, layout.x_offset, layout.x_bits), layout.x_bits));
    let y = (layout.y_bits != 0)
        .then(|| signed(bits(payload, layout.y_offset, layout.y_bits), layout.y_bits));
    let wheel = (layout.wheel_bits != 0).then(|| {
        signed(
            bits(payload, layout.wheel_offset, layout.wheel_bits),
            layout.wheel_bits,
        )
    });
    let mut line = LogStr::new();
    let _ = write!(
        line,
        "        hid_report application=mouse report_id={} buttons=0x{:02X}",
        if layout.has_report_id { value[0] } else { 0 },
        button
    );
    if let Some(x) = x {
        let _ = write!(line, " x={}", x);
    }
    if let Some(y) = y {
        let _ = write!(line, " y={}", y);
    }
    if let Some(wheel) = wheel {
        let _ = write!(line, " wheel={}", wheel);
    }
    Some(line)
}

/// Decode a standard HID Information characteristic (0x2A4A).
pub(crate) fn decode_hid_info(value: &[u8]) -> Option<(LogStr, usize)> {
    if value.len() < 4 {
        return None;
    }
    let bcd = u16::from_le_bytes([value[0], value[1]]);
    let flags = value[3];
    let mut line = LogStr::new();
    let _ = write!(
        line,
        "        hid_info bcd=0x{:04X} country={} flags=0x{:02X} remote_wake={} normally_connectable={}",
        bcd,
        value[2],
        flags,
        flags & 0x01 != 0,
        flags & 0x02 != 0
    );
    Some((line, 4))
}

/// Decode a value read from one of the standard HID-over-GATT characteristics.
pub(crate) fn decode_value(
    uuid16: u16,
    value: &[u8],
    layout: &HidLayout,
) -> Option<(LogStr, usize)> {
    match uuid16 {
        0x2A4A => decode_hid_info(value),
        0x2A4B => decode_report_map(value).map(|(line, used, _)| (line, used)),
        0x2A33 | 0x2A4D => {
            if let Some(line) = decode_input_report(value, layout) {
                return Some((line, value.len()));
            }
            // A few peers in the capture return their report map when the report
            // value is read. Keep that observable protocol quirk explicit.
            if value.len() > 16
                && value.first() == Some(&0x05)
                && let Some((mut line, used, _)) = decode_report_map(value)
            {
                let _ = write!(line, " report_value=report_map_like");
                return Some((line, used));
            }
            None
        }
        _ => None,
    }
}
