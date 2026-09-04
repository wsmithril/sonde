//! Per-appliance Midea codecs, dispatched by the M-Smart type code (`sn[8..10]`).
//!
//! Each appliance module implements that product's status decode, cross-checked
//! against the manufacturer's own protocol Lua (`meijia-decompile/lua/T_0000_*.lua`
//! — the decrypted per-type codecs). The transport (GATT/handshake/crypto/frame
//! wrapping) is shared and lives in the parent `device::midea`; only the
//! appliance-specific `0xC0` status bytes differ here.
//!
//! Each module exposes a uniform `write_status(t, w)` that decodes the status
//! reply and writes the one-line summary — the dispatcher routes on the type code.

pub mod air_conditioner; // 0xAC — full codec (build query/control + parse status)
pub mod air_purifier; // 0xFC — air purifier
pub mod dehumidifier; // 0xA1 — dehumidifier (from T_0000_A1)
pub mod dishwasher; // 0xE1
pub mod electric_heater;
pub mod fan; // 0xFA — fan (from T_0000_FA)
pub mod gas_water_heater; // 0xE3
pub mod heat_pump_water_heater; // 0xCD — heat-pump water heater (from T_0000_CD)
pub mod humidifier; // 0xFD — humidifier (from T_0000_FD)
pub mod light; // 0x13
pub mod m10; // 0x10
pub mod m17; // 0x17
pub mod m70; // 0x70
pub mod mb2; // 0xB2
pub mod mb4; // 0xB4
pub mod mb8; // 0xB8
pub mod mcc; // 0xCC
pub mod me7; // 0xE7
pub mod me8; // 0xE8
pub mod me9; // 0xE9
pub mod meb; // 0xEB
pub mod mef; // 0xEF
pub mod mf1; // 0xF1
pub mod microwave; // 0xB0 — microwave
pub mod pressure_cooker; // 0xEC — pressure cooker (from T_0000_EC)
pub mod range_hood; // 0xB6 — range hood
pub mod refrigerator; // 0xCA — refrigerator (from T_0000_CA)
pub mod rice_cooker; // 0xEA — rice cooker (from T_0000_EA)
pub mod t9a; // 0x9A
pub mod tb1; // 0xB1
pub mod washer_da; // 0xDA — top-load washer
pub mod washer_db; // 0xDB — front-load washer
pub mod water_dispenser; // 0xED
pub mod water_heater; // 0xE2 — electric water heater (from T_0000_E2) // 0xFB — electric heater

/// The M-Smart appliance type — the two-char device-type code from the serial
/// (`sn[8..10]`) as a typed enum, so the dispatcher is exhaustive and a code
/// can't silently fall through as a raw byte string.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Type {
    /// `AC` — air conditioner.
    AirConditioner,
    /// `E2` — electric water heater.
    WaterHeater,
    /// `CD` — heat-pump water heater.
    HeatPumpWaterHeater,
    /// `A1` — dehumidifier.
    Dehumidifier,
    /// `FD` — humidifier.
    Humidifier,
    /// `FA` — fan.
    Fan,
    /// `CA` — refrigerator.
    Refrigerator,
    /// `10`, `CC`, `B2`, `B4`, `B8`, `17`, `E7`, `E8`, `E9`, `EB`, `EF`, `F1` —
    /// ported, display name pending.
    T10,
    TCC,
    TB2,
    TB4,
    TB8,
    T17,
    T70,
    TE7,
    TE8,
    TE9,
    TEB,
    TEF,
    TF1,
    /// `EA` — rice cooker.
    RiceCooker,
    /// `EC` — pressure cooker.
    PressureCooker,
    /// `13`, `9A`, `B0`, `B1`, `B6`, `DA`, `DB`, `E1`, `E3`, `ED`, `FC` — ported.
    Light,
    T9A,
    Microwave,
    TB1,
    RangeHood,
    WasherDa,
    WasherDb,
    Dishwasher,
    GasWaterHeater,
    WaterDispenser,
    AirPurifier,
    ElectricHeater,
    // … more types as their Lua codecs are ported.
}

impl Type {
    /// Resolve a 2-byte type code (`sn[8..10]`) to a [`Type`]. `None` for codes
    /// with no ported decoder yet.
    pub fn from_code(c: &[u8]) -> Option<Self> {
        match c {
            b"AC" => Some(Self::AirConditioner),
            b"E2" => Some(Self::WaterHeater),
            b"CD" => Some(Self::HeatPumpWaterHeater),
            b"A1" => Some(Self::Dehumidifier),
            b"FD" => Some(Self::Humidifier),
            b"FA" => Some(Self::Fan),
            b"CA" => Some(Self::Refrigerator),
            b"10" => Some(Self::T10),
            b"CC" => Some(Self::TCC),
            b"B2" => Some(Self::TB2),
            b"B4" => Some(Self::TB4),
            b"B8" => Some(Self::TB8),
            b"17" => Some(Self::T17),
            b"70" => Some(Self::T70),
            b"E7" => Some(Self::TE7),
            b"E8" => Some(Self::TE8),
            b"E9" => Some(Self::TE9),
            b"EB" => Some(Self::TEB),
            b"EF" => Some(Self::TEF),
            b"F1" => Some(Self::TF1),
            b"EA" => Some(Self::RiceCooker),
            b"EC" => Some(Self::PressureCooker),
            b"13" => Some(Self::Light),
            b"9A" => Some(Self::T9A),
            b"B0" => Some(Self::Microwave),
            b"B1" => Some(Self::TB1),
            b"B6" => Some(Self::RangeHood),
            b"DA" => Some(Self::WasherDa),
            b"DB" => Some(Self::WasherDb),
            b"E1" => Some(Self::Dishwasher),
            b"E3" => Some(Self::GasWaterHeater),
            b"ED" => Some(Self::WaterDispenser),
            b"FC" => Some(Self::AirPurifier),
            b"FB" => Some(Self::ElectricHeater),
            _ => None,
        }
    }

    /// The 2-char wire code.
    pub fn code(self) -> &'static [u8; 2] {
        match self {
            Self::AirConditioner => b"AC",
            Self::WaterHeater => b"E2",
            Self::HeatPumpWaterHeater => b"CD",
            Self::Dehumidifier => b"A1",
            Self::Humidifier => b"FD",
            Self::Fan => b"FA",
            Self::Refrigerator => b"CA",
            Self::T10 => b"10",
            Self::TCC => b"CC",
            Self::TB2 => b"B2",
            Self::TB4 => b"B4",
            Self::TB8 => b"B8",
            Self::T17 => b"17",
            Self::T70 => b"70",
            Self::TE7 => b"E7",
            Self::TE8 => b"E8",
            Self::TE9 => b"E9",
            Self::TEB => b"EB",
            Self::TEF => b"EF",
            Self::TF1 => b"F1",
            Self::RiceCooker => b"EA",
            Self::PressureCooker => b"EC",
            Self::Light => b"13",
            Self::T9A => b"9A",
            Self::Microwave => b"B0",
            Self::TB1 => b"B1",
            Self::RangeHood => b"B6",
            Self::WasherDa => b"DA",
            Self::WasherDb => b"DB",
            Self::Dishwasher => b"E1",
            Self::GasWaterHeater => b"E3",
            Self::WaterDispenser => b"ED",
            Self::AirPurifier => b"FC",
            Self::ElectricHeater => b"FB",
        }
    }
}

/// Decode a Midea status reply for the given [`Type`] into `w`, routing to the
/// per-appliance decoder. Returns `false` when the frame is malformed.
pub fn write_status(t: Type, frame: &[u8], w: &mut impl core::fmt::Write) -> bool {
    match t {
        Type::AirConditioner => air_conditioner::write_status(frame, w),
        Type::WaterHeater => water_heater::write_status(frame, w),
        Type::HeatPumpWaterHeater => heat_pump_water_heater::write_status(frame, w),
        Type::Dehumidifier => dehumidifier::write_status(frame, w),
        Type::Humidifier => humidifier::write_status(frame, w),
        Type::Fan => fan::write_status(frame, w),
        Type::Refrigerator => refrigerator::write_status(frame, w),
        Type::T10 => m10::write_status(frame, w),
        Type::TCC => mcc::write_status(frame, w),
        Type::TB2 => mb2::write_status(frame, w),
        Type::TB4 => mb4::write_status(frame, w),
        Type::TB8 => mb8::write_status(frame, w),
        Type::T17 => m17::write_status(frame, w),
        Type::T70 => m70::write_status(frame, w),
        Type::TE7 => me7::write_status(frame, w),
        Type::TE8 => me8::write_status(frame, w),
        Type::TE9 => me9::write_status(frame, w),
        Type::TEB => meb::write_status(frame, w),
        Type::TEF => mef::write_status(frame, w),
        Type::TF1 => mf1::write_status(frame, w),
        Type::RiceCooker => rice_cooker::write_status(frame, w),
        Type::PressureCooker => pressure_cooker::write_status(frame, w),
        Type::Light => light::write_status(frame, w),
        Type::T9A => t9a::write_status(frame, w),
        Type::Microwave => microwave::write_status(frame, w),
        Type::TB1 => tb1::write_status(frame, w),
        Type::RangeHood => range_hood::write_status(frame, w),
        Type::WasherDa => washer_da::write_status(frame, w),
        Type::WasherDb => washer_db::write_status(frame, w),
        Type::Dishwasher => dishwasher::write_status(frame, w),
        Type::GasWaterHeater => gas_water_heater::write_status(frame, w),
        Type::WaterDispenser => water_dispenser::write_status(frame, w),
        Type::AirPurifier => air_purifier::write_status(frame, w),
        Type::ElectricHeater => electric_heater::write_status(frame, w),
    }
}

/// Build the status-query appliance frame for `t` — the `biz_body` the shared
/// t3 transport wraps (`build_biz(32, query, …)`). `None` when the type's Lua
/// template defines no query (its status may only arrive via auto-report or
/// control replies). AC and E2 currently have a query; more types can be added
/// as their `T_0000_*.lua` `getTotalMsg`/query construction is ported.
pub fn build_query(t: Type) -> Option<crate::device::midea::frame::Frame> {
    match t {
        Type::AirConditioner => Some(air_conditioner::build_query_frame(1, 0)),
        Type::WaterHeater => Some(water_heater::build_query()),
        _ => None,
    }
}
