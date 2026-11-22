//! Drone Remote ID, ASTM F3411 / ASD-STAN EN 4709-002 (service UUID 0xFFFA).
//!
//! The broadcast every registered drone must send. Layout after the UUID is
//! `[app code 0x0D][counter][message or message pack]`: one 25-byte message on
//! legacy advertising, a pack on extended advertising. Parsing is done by the
//! `remoteid` crate (no_std, no allocation); this module only formats.
//!
//! A Basic ID that claims to be an ANSI/CTA-2063-A serial but does not parse as
//! one is flagged: real aircraft burn a valid serial in at the factory, spoofing
//! tools type whatever they like.

use core::fmt::Write;

use remoteid::{IdType, Message, ble};

use super::{LogStr, emit, hexdump};

/// ASTM F3411 Remote ID (0xFFFA), service data.
pub(super) struct RemoteId;
impl super::VendorDecoder for RemoteId {
    fn service_uuids(&self) -> &'static [u16] {
        &[ble::SERVICE_UUID]
    }
    fn decode(&self, ctx: &super::DecodeCtx, body: &[u8]) {
        let mut s: LogStr = LogStr::new();
        let parsed = ble::parse_service_data(body).and_then(|r| Ok((r.counter, r.frame()?)));
        let (counter, frame) = match parsed {
            Ok(p) => p,
            Err(e) => {
                let _ = write!(s, "    Remote ID: undecodable ({})", e);
                emit(s);
                hexdump(body, ctx.base, 6);
                return;
            }
        };
        let _ = write!(s, "    Remote ID (ASTM F3411): counter={}", counter);
        emit(s);
        frame.for_each_message(|m| {
            let mut s: LogStr = LogStr::new();
            let _ = describe(&m, &mut s);
            emit(s);
        });
    }
}

/// One line per Remote ID message.
fn describe(m: &Message, s: &mut impl Write) -> core::fmt::Result {
    match m {
        Message::BasicId(b) => {
            write!(s, "      BasicId: {:?} {:?} id=", b.id_type, b.ua_type)?;
            match b.uas_id_str() {
                Some(id) => write!(s, "\"{}\"", id)?,
                None => write!(s, "<binary>")?,
            }
            if b.id_type == IdType::SerialNumber && b.serial_number().is_none() {
                write!(s, " SUSPECT: not a valid ANSI/CTA-2063-A serial")?;
            }
        }
        Message::Location(l) => {
            write!(s, "      Location: {:?}", l.status)?;
            match l.position() {
                Some((lat, lon)) => write!(s, " lat={:.6} lon={:.6}", lat, lon)?,
                None => write!(s, " pos=unknown")?,
            }
            if let Some(a) = l.altitude_geo {
                write!(s, " alt={:.1}m", a)?;
            }
            if let Some(v) = l.speed_horizontal {
                write!(s, " spd={:.2}m/s", v)?;
            }
            if let Some(d) = l.direction {
                write!(s, " hdg={:.0}", d)?;
            }
        }
        Message::Auth(a) => write!(s, "      Auth: {:?} page={}", a.auth_type, a.page)?,
        Message::SelfId(d) => write!(s, "      SelfId: \"{}\"", d.description_str().unwrap_or(""))?,
        Message::System(y) => {
            write!(s, "      System: {:?}", y.operator_location_type)?;
            if let Some((lat, lon)) = y.operator_position() {
                write!(s, " operator lat={:.6} lon={:.6}", lat, lon)?;
            }
        }
        Message::OperatorId(o) => write!(
            s,
            "      OperatorId: \"{}\"",
            o.operator_id_str().unwrap_or("")
        )?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::describe;
    use remoteid::{BasicId, IdType, Location, Message, UaType, ble};

    fn line(m: &Message) -> heapless::String<256> {
        let mut s = heapless::String::new();
        describe(m, &mut s).unwrap();
        s
    }

    fn body_of(raw: &[u8; 25]) -> heapless::Vec<u8, 31> {
        let mut out = [0u8; 31];
        let n = ble::write_advertising_data(7, raw, &mut out).unwrap();
        // Drop [len][0x16][UUID lo][UUID hi]: the decoder gets the bytes after the UUID.
        heapless::Vec::from_slice(&out[4..n]).unwrap()
    }

    #[test]
    fn decodes_basic_id_and_location_from_service_data() {
        let id = BasicId::new(
            IdType::SerialNumber,
            UaType::HelicopterOrMultirotor,
            "1596A3ZXT8W1BCD",
        )
        .unwrap();
        let body = body_of(&id.encode().unwrap());
        let r = ble::parse_service_data(&body).unwrap();
        assert_eq!(r.counter, 7);
        let mut got = None;
        r.frame()
            .unwrap()
            .for_each_message(|m| got = Some(line(&m)));
        let got = got.unwrap();
        assert!(got.contains("\"1596A3ZXT8W1BCD\""), "{got}");
        assert!(!got.contains("SUSPECT"), "{got}");

        let loc = Location {
            latitude: 47.3977,
            longitude: 8.5456,
            altitude_geo: Some(120.0),
            ..Location::default()
        };
        let got = line(&Message::Location(loc));
        assert!(
            got.contains("lat=47.397") && got.contains("lon=8.545"),
            "{got}"
        );
    }

    #[test]
    fn flags_a_serial_that_breaks_cta_2063() {
        let id = BasicId::new(
            IdType::SerialNumber,
            UaType::HelicopterOrMultirotor,
            "FAKE-DRONE-01",
        )
        .unwrap();
        assert!(line(&Message::BasicId(id)).contains("SUSPECT"));
    }
}
