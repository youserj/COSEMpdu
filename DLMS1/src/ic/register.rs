//! COSEM interface class "Register" (class_id 3, version 0).

use cosempdu::buffer::ByteBuffer;
use cosempdu::data::{Data, FromStructure};

use crate::error::{Error, Result};
use crate::ic::{
    Attribute, AttributeInfo, AttributeKey, AttributeType, ClassId, Classifier,
    InterfaceClass, Validator, V0,
};
use crate::obis::ObisCode;

/// Attribute 1 — `logical_name` (octet-string).
pub const ATTR_LOGICAL_NAME: u8 = 1;
/// Attribute 2 — `value` (instance-specific).
pub const ATTR_VALUE: u8 = 2;
/// Attribute 3 — `scaler_unit`.
pub const ATTR_SCALER_UNIT: u8 = 3;

/// Tags of the `simple-data-type` CHOICE (the `value` of Register / Extended register).
pub const SIMPLE_DATA_TAGS: &[u8] =
    &[0, 4, 5, 6, 9, 10, 12, 15, 16, 17, 18, 20, 21, 22, 23, 24];


/// `scal_unit_type ::= structure { scaler: integer, unit: enum }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalUnit {
    /// The scaler (power of ten multiplier).
    pub scaler: i8,
    /// The unit (enumeration, per DLMS UA 1000-1).
    pub unit: u8,
}

impl ScalUnit {
    pub const fn new(scaler: i8, unit: u8) -> Self {
        ScalUnit { scaler, unit }
    }

    /// Unitless default: scaler 0, unit 255.
    pub const UNITLESS: Self = ScalUnit {
        scaler: 0,
        unit: 255,
    };
}

impl<'a> FromStructure<'a> for ScalUnit {
    fn from_structure(fields: &'a [Data<'a>]) -> cosempdu::Result<Self> {
        if fields.len() != 2 {
            return Err(cosempdu::Error::Message("expected structure { integer, enum }"));
        }
        let scaler = fields[0]
            .as_integer()
            .ok_or(cosempdu::Error::Message("field 0 must be integer"))?;
        let unit = fields[1]
            .as_enum()
            .ok_or(cosempdu::Error::Message("field 1 must be enum"))?;
        Ok(ScalUnit { scaler, unit })
    }
}

impl Attribute for ScalUnit {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        Ok(Data::Structure(&[Data::Integer(self.scaler), Data::Enum(self.unit)]).put(buf)?)
    }

    fn assign(&mut self, data: &Data<'_>) -> Result<()> {
        *self = data.recast::<ScalUnit>()?;
        Ok(())
    }
}

/// Validates a `scal_unit_type` value.
#[derive(Debug)]
pub struct ScalUnitValidator;

impl Validator for ScalUnitValidator {
    fn validate(&self, data: &Data<'_>) -> Result<()> {
        data.recast::<ScalUnit>().map(|_| ()).map_err(Error::from)
    }
}

/// Static `scal_unit_type` validator (as a trait object).
pub const SCAL_UNIT_VALIDATOR: &dyn Validator = &ScalUnitValidator;

/// Generates the `value`/`scaler_unit` attribute-key methods, shared by
/// register-like classes (Register, ExtendedRegister, …).
macro_rules! register_value_keys {
    () => {
        /// Key of the `value` attribute.
        pub fn value(&self) -> AttributeKey {
            AttributeKey::new(self.obis, ATTR_VALUE)
        }

        /// Key of the `scaler_unit` attribute.
        pub fn scaler_unit(&self) -> AttributeKey {
            AttributeKey::new(self.obis, ATTR_SCALER_UNIT)
        }
    };
}
pub(crate) use register_value_keys;

/// COSEM interface class "Register" (class_id 3): a static object descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register {
    pub obis: ObisCode,
}

impl Register {
    pub const fn new(obis: ObisCode) -> Self {
        Register { obis }
    }

    register_value_keys!();
}

impl InterfaceClass for Register {
    fn class_id(&self) -> ClassId {
        ClassId::Register
    }

    fn version(&self) -> u8 {
        V0
    }

    fn obis(&self) -> ObisCode {
        self.obis
    }

    fn attributes(&self) -> &'static [AttributeInfo] {
        &[
            AttributeInfo {
                data_type: AttributeType::Choice(SIMPLE_DATA_TAGS),
                min: None,
                max: None,
                default: Some(Data::DoubleLongUnsigned(0)),
                classifier: Classifier::Dynamic,
            },
            AttributeInfo {
                data_type: AttributeType::Validator(SCAL_UNIT_VALIDATOR),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Static,
            },
        ]
    }
}
