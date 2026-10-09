//! OBIS Object Identification System (DLMS UA 1000-1 Ed. 14, clause 4).
//!
//! An OBIS code identifies a COSEM object instance as six value groups
//! `A.B.C.D.E.F`, each one byte. This module provides the [`ObisCode`] type, its
//! logical-name (6-byte octet-string) form, the value-group enumerations and the
//! short-name (SN) base-name mapping.

use core::fmt;
use core::str::FromStr;

use crate::error::{Error, Result};

/// A COSEM OBIS code: six value groups `A.B.C.D.E.F`.
///
/// - `A` — medium / energy type ([`Medium`])
/// - `B` — channel (0..64)
/// - `C` — physical quantity ([`Quantity`])
/// - `D` — processing ([`Processing`])
/// - `E` — tariff rate / register (0 = total, 1..63 = rates)
/// - `F` — billing period / historical ([`Period`])
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObisCode {
    /// The six bytes A (medium), B (channel), C (quantity), D (processing),
    /// E (tariff) and F (period).
    pub bytes: [u8; 6],
}

impl ObisCode {
    /// Build an OBIS code from its six value groups.
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        ObisCode {
            bytes: [a, b, c, d, e, f],
        }
    }

    /// Build an OBIS code from a raw 6-byte array.
    pub const fn from_bytes(bytes: [u8; 6]) -> Self {
        ObisCode { bytes }
    }

    /// Value group A — medium / energy type.
    pub const fn a(&self) -> u8 {
        self.bytes[0]
    }
    /// Value group B — channel.
    pub const fn b(&self) -> u8 {
        self.bytes[1]
    }
    /// Value group C — physical quantity.
    pub const fn c(&self) -> u8 {
        self.bytes[2]
    }
    /// Value group D — processing.
    pub const fn d(&self) -> u8 {
        self.bytes[3]
    }
    /// Value group E — tariff rate / register.
    pub const fn e(&self) -> u8 {
        self.bytes[4]
    }
    /// Value group F — billing period / historical.
    pub const fn f(&self) -> u8 {
        self.bytes[5]
    }

    /// The logical-name form: the OBIS code as a 6-byte octet-string.
    pub const fn logical_name(&self) -> [u8; 6] {
        self.bytes
    }

    /// Parse the logical-name (6-byte octet-string) form.
    pub fn from_logical_name(ln: &[u8]) -> Result<Self> {
        if ln.len() != 6 {
            return Err(Error::InvalidObis);
        }
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(ln);
        Ok(ObisCode { bytes })
    }

    /// The 16-bit SN (short-name) *base name* (clause 4.8).
    ///
    /// Only value groups A..D contribute; E and F are addressed via the SN
    /// instance/offset mechanism and are therefore not part of the base name:
    ///
    /// ```text
    /// base_name = ((A & 0x0F) << 12) | ((B & 0x0F) << 8) | ((C & 0x0F) << 4) | (D & 0x0F)
    /// ```
    pub const fn base_name(&self) -> u16 {
        (((self.a() & 0x0F) as u16) << 12)
            | (((self.b() & 0x0F) as u16) << 8)
            | (((self.c() & 0x0F) as u16) << 4)
            | ((self.d() & 0x0F) as u16)
    }

    /// Reconstruct an OBIS code from an SN base name.
    ///
    /// The inverse mapping is lossy: E and F are not stored in the base name and
    /// are set to `0` (total / current period) here.
    pub const fn from_base_name(base: u16) -> Self {
        ObisCode::new(
            ((base >> 12) & 0x0F) as u8,
            ((base >> 8) & 0x0F) as u8,
            ((base >> 4) & 0x0F) as u8,
            (base & 0x0F) as u8,
            0,
            0,
        )
    }

    /// The clock object: `0.0.1.0.0.255`.
    pub const CLOCK: ObisCode = ObisCode::new(0, 0, 1, 0, 0, 255);
    /// The current (LN) association: `0.0.40.0.0.255`.
    pub const ASSOCIATION_LN: ObisCode = ObisCode::new(0, 0, 40, 0, 0, 255);
    /// Total active energy import (+A): `1.0.1.8.0.255`.
    pub const ACTIVE_ENERGY_IMPORT_TOTAL: ObisCode = ObisCode::new(1, 0, 1, 8, 0, 255);
    /// Total active energy export (−A): `1.0.2.8.0.255`.
    pub const ACTIVE_ENERGY_EXPORT_TOTAL: ObisCode = ObisCode::new(1, 0, 2, 8, 0, 255);
    /// Total reactive energy import (+R): `1.0.3.8.0.255`.
    pub const REACTIVE_ENERGY_IMPORT_TOTAL: ObisCode = ObisCode::new(1, 0, 3, 8, 0, 255);
    /// Total reactive energy export (−R): `1.0.4.8.0.255`.
    pub const REACTIVE_ENERGY_EXPORT_TOTAL: ObisCode = ObisCode::new(1, 0, 4, 8, 0, 255);
}

impl fmt::Display for ObisCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}.{}.{}",
            self.a(),
            self.b(),
            self.c(),
            self.d(),
            self.e(),
            self.f()
        )
    }
}

impl FromStr for ObisCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split('.');
        let mut bytes = [0u8; 6];
        for slot in bytes.iter_mut() {
            let part = parts.next().ok_or(Error::InvalidObis)?;
            *slot = part.parse::<u8>().map_err(|_| Error::InvalidObis)?;
        }
        if parts.next().is_some() {
            return Err(Error::InvalidObis);
        }
        Ok(ObisCode { bytes })
    }
}

/// Value group A — medium / energy type (clause 4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Medium {
    /// Abstract objects.
    Abstract = 0,
    /// Electricity.
    Electricity = 1,
    /// Heat cost allocator.
    HeatCostAllocator = 4,
    /// Cooling.
    Cooling = 5,
    /// Heat (outstation).
    Heat = 6,
    /// Gas.
    Gas = 7,
    /// Cold water.
    ColdWater = 8,
    /// Hot water.
    HotWater = 9,
    /// Other medium.
    OtherMedium = 15,
}

impl Medium {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Medium::Abstract),
            1 => Some(Medium::Electricity),
            4 => Some(Medium::HeatCostAllocator),
            5 => Some(Medium::Cooling),
            6 => Some(Medium::Heat),
            7 => Some(Medium::Gas),
            8 => Some(Medium::ColdWater),
            9 => Some(Medium::HotWater),
            15 => Some(Medium::OtherMedium),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Value group C — physical quantity (clause 4.1.3).
///
/// The same quantity codes are reused for power and energy; value group D
/// ([`Processing`]) distinguishes an instantaneous value from an integral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Quantity {
    /// General purpose / abstract.
    GeneralPurpose = 0,
    /// Active power / energy, positive (import).
    ActivePowerPlus = 1,
    /// Active power / energy, negative (export).
    ActivePowerMinus = 2,
    /// Reactive power / energy, positive (import).
    ReactivePowerPlus = 3,
    /// Reactive power / energy, negative (export).
    ReactivePowerMinus = 4,
    /// Reactive power / energy, quadrant I.
    ReactivePowerQI = 5,
    /// Reactive power / energy, quadrant II.
    ReactivePowerQII = 6,
    /// Reactive power / energy, quadrant III.
    ReactivePowerQIII = 7,
    /// Reactive power / energy, quadrant IV.
    ReactivePowerQIV = 8,
    /// Apparent power / energy, positive.
    ApparentPowerPlus = 9,
    /// Apparent power / energy, negative.
    ApparentPowerMinus = 10,
    /// Current.
    Current = 11,
    /// Voltage.
    Voltage = 12,
    /// Power factor.
    PowerFactor = 13,
    /// Supply frequency.
    SupplyFrequency = 14,
}

impl Quantity {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Quantity::GeneralPurpose),
            1 => Some(Quantity::ActivePowerPlus),
            2 => Some(Quantity::ActivePowerMinus),
            3 => Some(Quantity::ReactivePowerPlus),
            4 => Some(Quantity::ReactivePowerMinus),
            5 => Some(Quantity::ReactivePowerQI),
            6 => Some(Quantity::ReactivePowerQII),
            7 => Some(Quantity::ReactivePowerQIII),
            8 => Some(Quantity::ReactivePowerQIV),
            9 => Some(Quantity::ApparentPowerPlus),
            10 => Some(Quantity::ApparentPowerMinus),
            11 => Some(Quantity::Current),
            12 => Some(Quantity::Voltage),
            13 => Some(Quantity::PowerFactor),
            14 => Some(Quantity::SupplyFrequency),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Value group D — processing (clause 4.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Processing {
    /// The instantaneous value of the physical quantity.
    Value = 0,
    /// Maximum demand / value 1.
    Maximum1 = 1,
    /// Maximum demand / value 2.
    Maximum2 = 2,
    /// Minimum demand / value 1.
    Minimum1 = 3,
    /// Minimum demand / value 2.
    Minimum2 = 4,
    /// Integral 1 (time integral — energy).
    Integral1 = 8,
    /// Integral 2.
    Integral2 = 9,
    /// Integral 3.
    Integral3 = 10,
    /// Integral 4.
    Integral4 = 11,
}

impl Processing {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Processing::Value),
            1 => Some(Processing::Maximum1),
            2 => Some(Processing::Maximum2),
            3 => Some(Processing::Minimum1),
            4 => Some(Processing::Minimum2),
            8 => Some(Processing::Integral1),
            9 => Some(Processing::Integral2),
            10 => Some(Processing::Integral3),
            11 => Some(Processing::Integral4),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Value group F — billing period / historical (clause 4.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Period {
    /// The current (not yet settled) value.
    Current = 0,
    /// Billing period 1 (previous).
    BillingPeriod1 = 1,
    /// Billing period 2.
    BillingPeriod2 = 2,
    /// Billing period 3.
    BillingPeriod3 = 3,
    /// Billing period 4.
    BillingPeriod4 = 4,
    /// Billing period 5.
    BillingPeriod5 = 5,
    /// Not applicable / all periods.
    NotApplicable = 255,
}

impl Period {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Period::Current),
            1 => Some(Period::BillingPeriod1),
            2 => Some(Period::BillingPeriod2),
            3 => Some(Period::BillingPeriod3),
            4 => Some(Period::BillingPeriod4),
            5 => Some(Period::BillingPeriod5),
            255 => Some(Period::NotApplicable),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_roundtrip() {
        let code: ObisCode = "1.0.1.8.0.255".parse().unwrap();
        assert_eq!(code.bytes, [1, 0, 1, 8, 0, 255]);
        assert_eq!(code.to_string(), "1.0.1.8.0.255");
        assert_eq!(code.a(), 1);
        assert_eq!(code.c(), 1);
        assert_eq!(code.d(), 8);
        assert_eq!(code.f(), 255);
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!("1.0.1.8".parse::<ObisCode>().is_err());
        assert!("1.0.1.8.0.255.7".parse::<ObisCode>().is_err());
        assert!("x.0.1.8.0.255".parse::<ObisCode>().is_err());
    }

    #[test]
    fn logical_name_roundtrip() {
        let code = ObisCode::new(1, 0, 1, 8, 0, 255);
        assert_eq!(code.logical_name(), [1, 0, 1, 8, 0, 255]);
        assert_eq!(ObisCode::from_logical_name(&[1, 0, 1, 8, 0, 255]).unwrap(), code);
        assert!(ObisCode::from_logical_name(&[1, 0, 1, 8, 0]).is_err());
    }

    #[test]
    fn base_name_mapping() {
        // +A total (1.0.1.8.0.255): base = 0x1018.
        assert_eq!(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL.base_name(), 0x1018);
        // Clock (0.0.1.0.0.255): base = 0x0010.
        assert_eq!(ObisCode::CLOCK.base_name(), 0x0010);
        // Inverse is lossy for E/F.
        assert_eq!(ObisCode::from_base_name(0x1018).to_string(), "1.0.1.8.0.0");
    }

    #[test]
    fn value_group_enums() {
        assert_eq!(Medium::from_u8(1), Some(Medium::Electricity));
        assert_eq!(Medium::from_u8(3), None);
        assert_eq!(Quantity::from_u8(8), Some(Quantity::ReactivePowerQIV));
        assert_eq!(Processing::from_u8(8), Some(Processing::Integral1));
        assert_eq!(Period::from_u8(255), Some(Period::NotApplicable));
    }
}
