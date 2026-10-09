//! COSEM interface class "Association LN" (class_id 15, version 5).

use cosempdu::data::Data;

use crate::ic::{
    AttributeInfo, AttributeKey, AttributeType, ClassId, Classifier, CommonDataType,
    InterfaceClass, V5,
};
use crate::obis::ObisCode;

/// Attribute 1 — `logical_name` (octet-string).
pub const ATTR_LOGICAL_NAME: u8 = 1;
/// Attribute 2 — `object_list`.
pub const ATTR_OBJECT_LIST: u8 = 2;
/// Attribute 3 — `associated_partners_id` (visible-string).
pub const ATTR_ASSOCIATED_PARTNERS_ID: u8 = 3;
/// Attribute 4 — `application_context_name` (octet-string).
pub const ATTR_APPLICATION_CONTEXT_NAME: u8 = 4;
/// Attribute 5 — `xDLMS_context_info`.
pub const ATTR_XDLMS_CONTEXT_INFO: u8 = 5;
/// Attribute 6 — `authentication_mechanism_name` (enum).
pub const ATTR_AUTHENTICATION_MECHANISM_NAME: u8 = 6;
/// Attribute 7 — `LLS_secret` (octet-string).
pub const ATTR_LLS_SECRET: u8 = 7;
/// Attribute 8 — `association_status` (enum).
pub const ATTR_ASSOCIATION_STATUS: u8 = 8;
/// Attribute 9 — `security_setup_reference` (octet-string).
pub const ATTR_SECURITY_SETUP_REFERENCE: u8 = 9;

/// COSEM interface class "Association LN" (class_id 15): a static object descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssociationLn {
    pub obis: ObisCode,
}

impl AssociationLn {
    pub const fn new(obis: ObisCode) -> Self {
        AssociationLn { obis }
    }

    /// Key of the `object_list` attribute.
    pub fn object_list(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_OBJECT_LIST)
    }

    /// Key of the `associated_partners_id` attribute.
    pub fn associated_partners_id(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_ASSOCIATED_PARTNERS_ID)
    }

    /// Key of the `application_context_name` attribute.
    pub fn application_context_name(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_APPLICATION_CONTEXT_NAME)
    }

    /// Key of the `xDLMS_context_info` attribute.
    pub fn xdlms_context_info(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_XDLMS_CONTEXT_INFO)
    }

    /// Key of the `authentication_mechanism_name` attribute.
    pub fn authentication_mechanism_name(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_AUTHENTICATION_MECHANISM_NAME)
    }

    /// Key of the `LLS_secret` attribute.
    pub fn lls_secret(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_LLS_SECRET)
    }

    /// Key of the `association_status` attribute.
    pub fn association_status(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_ASSOCIATION_STATUS)
    }

    /// Key of the `security_setup_reference` attribute.
    pub fn security_setup_reference(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_SECURITY_SETUP_REFERENCE)
    }
}

impl InterfaceClass for AssociationLn {
    fn class_id(&self) -> ClassId {
        ClassId::AssociationLn
    }

    fn version(&self) -> u8 {
        V5
    }

    fn obis(&self) -> ObisCode {
        self.obis
    }

    fn attributes(&self) -> &'static [AttributeInfo] {
        &[
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::Array),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Dynamic,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::VisibleString),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Dynamic,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::OctetString),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::Structure),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::Enum),
                min: None,
                max: None,
                default: Some(Data::Enum(0)),
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::OctetString),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::Enum),
                min: None,
                max: None,
                default: Some(Data::Enum(0)),
                classifier: Classifier::Dynamic,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::OctetString),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Static,
            },
        ]
    }
}
