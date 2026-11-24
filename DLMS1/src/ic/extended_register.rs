//! COSEM interface class "Extended register" (class_id 4, version 0).

use cosempdu::data::Data;

use crate::ic::register::{register_value_keys, SIMPLE_DATA_TAGS};
use crate::ic::{
    AttributeInfo, AttributeKey, AttributeType, ClassId, Classifier, CommonDataType,
    InterfaceClass, SCAL_UNIT_VALIDATOR, V0,
};
use crate::obis::ObisCode;

/// Attribute 1 — `logical_name` (octet-string).
pub const ATTR_LOGICAL_NAME: i8 = 1;
/// Attribute 2 — `value` (instance-specific).
pub const ATTR_VALUE: i8 = 2;
/// Attribute 3 — `scaler_unit`.
pub const ATTR_SCALER_UNIT: i8 = 3;
/// Attribute 4 — `status` (bit-string).
pub const ATTR_STATUS: i8 = 4;
/// Attribute 5 — `capture_time` (date-time).
pub const ATTR_CAPTURE_TIME: i8 = 5;

/// COSEM interface class "Extended register" (class_id 4): a static object descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedRegister {
    pub obis: ObisCode,
}

impl ExtendedRegister {
    pub const fn new(obis: ObisCode) -> Self {
        ExtendedRegister { obis }
    }

    register_value_keys!();

    /// Key of the `status` attribute.
    pub const fn status(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_STATUS)
    }

    /// Key of the `capture_time` attribute.
    pub const fn capture_time(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_CAPTURE_TIME)
    }
}

impl InterfaceClass for ExtendedRegister {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn class_id(&self) -> ClassId {
        ClassId::ExtendedRegister
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
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::BitString),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Dynamic,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::DateTime),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Dynamic,
            },
        ]
    }
}
