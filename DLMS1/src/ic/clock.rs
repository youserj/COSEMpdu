//! COSEM interface class "Clock" (class_id 8, version 0).

use cosempdu::data::Data;

use crate::ic::{
    AttributeInfo, AttributeKey, AttributeType, ClassId, Classifier, CommonDataType,
    InterfaceClass, V0,
};
use crate::obis::ObisCode;

/// Attribute 1 — `logical_name` (octet-string).
pub const ATTR_LOGICAL_NAME: u8 = 1;
/// Attribute 2 — `time` (date-time).
pub const ATTR_TIME: u8 = 2;
/// Attribute 3 — `time_zone` (long).
pub const ATTR_TIME_ZONE: u8 = 3;
/// Attribute 4 — `status` (unsigned).
pub const ATTR_STATUS: u8 = 4;
/// Attribute 5 — `begin` (date-time).
pub const ATTR_BEGIN: u8 = 5;
/// Attribute 6 — `end` (date-time).
pub const ATTR_END: u8 = 6;
/// Attribute 7 — `deviation` (long).
pub const ATTR_DEVIATION: u8 = 7;
/// Attribute 8 — `clock_base` (enum).
pub const ATTR_CLOCK_BASE: u8 = 8;

/// COSEM interface class "Clock" (class_id 8): a static object descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    pub obis: ObisCode,
}

impl Clock {
    pub const fn new(obis: ObisCode) -> Self {
        Clock { obis }
    }

    /// Key of the `time` attribute.
    pub fn time(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_TIME)
    }

    /// Key of the `time_zone` attribute.
    pub fn time_zone(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_TIME_ZONE)
    }

    /// Key of the `status` attribute.
    pub fn status(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_STATUS)
    }

    /// Key of the `begin` attribute.
    pub fn begin(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_BEGIN)
    }

    /// Key of the `end` attribute.
    pub fn end(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_END)
    }

    /// Key of the `deviation` attribute.
    pub fn deviation(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_DEVIATION)
    }

    /// Key of the `clock_base` attribute.
    pub fn clock_base(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_CLOCK_BASE)
    }
}

impl InterfaceClass for Clock {
    fn class_id(&self) -> ClassId {
        ClassId::Clock
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
                data_type: AttributeType::Common(CommonDataType::DateTime),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Dynamic,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::Long),
                min: Some(Data::Long(-720)),
                max: Some(Data::Long(720)),
                default: Some(Data::Long(0)),
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::Unsigned),
                min: None,
                max: None,
                default: Some(Data::Unsigned(0)),
                classifier: Classifier::Dynamic,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::DateTime),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::DateTime),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::Long),
                min: Some(Data::Long(-900)),
                max: Some(Data::Long(900)),
                default: Some(Data::Long(0)),
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::Enum),
                min: None,
                max: None,
                default: Some(Data::Enum(0)),
                classifier: Classifier::Static,
            },
        ]
    }
}
