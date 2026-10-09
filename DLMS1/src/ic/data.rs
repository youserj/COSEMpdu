//! COSEM interface class "Data" (class_id 1, version 0).

use crate::ic::{AttributeInfo, AttributeKey, AttributeType, ClassId, Classifier, InterfaceClass, V0};
use crate::obis::ObisCode;

/// Attribute 1 — `logical_name` (octet-string).
pub const ATTR_LOGICAL_NAME: u8 = 1;
/// Attribute 2 — `value` (instance-specific).
pub const ATTR_VALUE: u8 = 2;

/// COSEM interface class "Data" (class_id 1): a static object descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataObject {
    pub obis: ObisCode,
}

impl DataObject {
    pub const fn new(obis: ObisCode) -> Self {
        DataObject { obis }
    }

    /// Key of the `value` attribute.
    pub fn value(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_VALUE)
    }
}

impl InterfaceClass for DataObject {
    fn class_id(&self) -> ClassId {
        ClassId::Data
    }

    fn version(&self) -> u8 {
        V0
    }

    fn obis(&self) -> ObisCode {
        self.obis
    }

    fn attributes(&self) -> &'static [AttributeInfo] {
        &[AttributeInfo {
            data_type: AttributeType::Data,
            min: None,
            max: None,
            default: None,
            classifier: Classifier::NotDefined,
        }]
    }
}
