//! COSEM interface class "Association LN" (class_id 15, version 1).

use cosempdu::axdr::put_length;
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::{Codec, Data, Encodable, FromStructure};

use crate::common_data_types::Array;
use crate::error::{Error, Result};
use crate::ic::{
    AttributeInfo, AttributeKey, AttributeType, ClassId, Classifier, CommonDataType,
    InterfaceClass, Validator, ASSOCIATED_PARTNERS_VALIDATOR, V1, XDLMS_CONTEXT_INFO_VALIDATOR,
};
use crate::obis::ObisCode;

/// Standard client_SAP (Service Access Point) values for client access levels.
///
/// `HLS` (High Level Security, `0x40`) is not used yet — it is planned
/// as a separate `feature` (authenticated/encrypted sessions).
pub mod client_sap {
    /// Public client.
    pub const PUBLIC: u8 = 0x10;
    /// Reader.
    pub const READER: u8 = 0x20;
    /// Configurator.
    pub const CONFIGURATOR: u8 = 0x30;
}

/// Attribute 1 — `logical_name` (octet-string).
pub const ATTR_LOGICAL_NAME: u8 = 1;
/// Attribute 2 — `object_list` (`object_list_type`).
pub const ATTR_OBJECT_LIST: u8 = 2;
/// Attribute 3 — `associated_partners_id` (`associated_partners_type`).
pub const ATTR_ASSOCIATED_PARTNERS_ID: u8 = 3;
/// Attribute 4 — `application_context_name` (`context_name_type`).
pub const ATTR_APPLICATION_CONTEXT_NAME: u8 = 4;
/// Attribute 5 — `xDLMS_context_info` (`xDLMS_context_type`).
pub const ATTR_XDLMS_CONTEXT_INFO: u8 = 5;
/// Attribute 6 — `authentication_mechanism_name` (`mechanism_name_type`).
pub const ATTR_AUTHENTICATION_MECHANISM_NAME: u8 = 6;
/// Attribute 7 — `secret` (octet-string).
pub const ATTR_SECRET: u8 = 7;
/// Attribute 8 — `association_status` (enum).
pub const ATTR_ASSOCIATION_STATUS: u8 = 8;
/// Attribute 9 — `security_setup_reference` (octet-string).
pub const ATTR_SECURITY_SETUP_REFERENCE: u8 = 9;

/// Method 1 — `reply_to_HLS_authentication` (data).
pub const METHOD_REPLY_TO_HLS_AUTHENTICATION: u8 = 1;
/// Method 2 — `change_HLS_secret` (data).
pub const METHOD_CHANGE_HLS_SECRET: u8 = 2;
/// Method 3 — `add_object` (data).
pub const METHOD_ADD_OBJECT: u8 = 3;
/// Method 4 — `remove_object` (data).
pub const METHOD_REMOVE_OBJECT: u8 = 4;

/// `access_mode` of an attribute entry in `object_list` (0..6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttributeAccessMode {
    NoAccess = 0,
    ReadOnly = 1,
    WriteOnly = 2,
    ReadAndWrite = 3,
    AuthenticatedReadOnly = 4,
    AuthenticatedWriteOnly = 5,
    AuthenticatedReadAndWrite = 6,
}

impl AttributeAccessMode {
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::NoAccess,
            1 => Self::ReadOnly,
            2 => Self::WriteOnly,
            3 => Self::ReadAndWrite,
            4 => Self::AuthenticatedReadOnly,
            5 => Self::AuthenticatedWriteOnly,
            6 => Self::AuthenticatedReadAndWrite,
            _ => return None,
        })
    }

    /// Reading (GET) is allowed for this access mode.
    pub const fn can_read(self, authenticated: bool) -> bool {
        match self {
            Self::ReadOnly | Self::ReadAndWrite => true,
            Self::AuthenticatedReadOnly | Self::AuthenticatedReadAndWrite => authenticated,
            _ => false,
        }
    }

    /// Writing (SET) is allowed for this access mode.
    pub const fn can_write(self, authenticated: bool) -> bool {
        match self {
            Self::WriteOnly | Self::ReadAndWrite => true,
            Self::AuthenticatedWriteOnly | Self::AuthenticatedReadAndWrite => authenticated,
            _ => false,
        }
    }
}

/// `access_mode` of a method entry in `object_list` (0..2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MethodAccessMode {
    NoAccess = 0,
    Access = 1,
    AuthenticatedAccess = 2,
}

impl MethodAccessMode {
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::NoAccess,
            1 => Self::Access,
            2 => Self::AuthenticatedAccess,
            _ => return None,
        })
    }

    /// Method invocation (ACTION) is allowed for this access mode.
    pub const fn can_call(self, authenticated: bool) -> bool {
        match self {
            Self::Access => true,
            Self::AuthenticatedAccess => authenticated,
            Self::NoAccess => false,
        }
    }
}

/// `array integer` — borrowed view over a slice of `integer` (i8) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArrayInteger<'a> {
    /// The integer values.
    pub data: &'a [i8],
}

impl<'a> Encodable for ArrayInteger<'a> {
    /// Encode this `array integer` (A-XDR array of integer).
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        let mut written = buf.put_u8(1)?; // array tag
        written += put_length(buf, self.data.len())?;
        for &v in self.data {
            written += Data::Integer(v).put(buf)?;
        }
        Ok(written)
    }
}

/// `access_selectors ::= CHOICE { null-data [0], array integer [1] }`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AccessSelectors<'a> {
    /// No selectors (null-data).
    Null,
    /// A list of integer selector values.
    Integers(ArrayInteger<'a>),
}

impl<'a> Encodable for AccessSelectors<'a> {
    /// Encode this CHOICE (null-data or array of integer).
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        match self {
            AccessSelectors::Null => Data::NullData.put(buf),
            AccessSelectors::Integers(arr) => arr.put(buf),
        }
    }
}

/// `attribute_access_item ::= structure { attribute_id: integer, access_mode: enum, access_selectors: access_selectors }`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttributeAccessItem<'a> {
    pub attribute_id: i8,
    pub access_mode: AttributeAccessMode,
    pub access_selectors: AccessSelectors<'a>,
}

impl<'a> Encodable for AttributeAccessItem<'a> {
    /// Encode this structure.
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        let mut written = buf.put_u8(2)?; // structure tag
        written += put_length(buf, 3)?;
        written += Data::Integer(self.attribute_id).put(buf)?;
        written += Data::Enum(self.access_mode as u8).put(buf)?;
        written += self.access_selectors.put(buf)?;
        Ok(written)
    }
}

/// `method_access_item ::= structure { method_id: integer, access_mode: enum }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodAccessItem {
    pub method_id: i8,
    pub access_mode: MethodAccessMode,
}

impl Encodable for MethodAccessItem {
    /// Encode this structure.
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        let mut written = buf.put_u8(2)?; // structure tag
        written += put_length(buf, 2)?;
        written += Data::Integer(self.method_id).put(buf)?;
        written += Data::Enum(self.access_mode as u8).put(buf)?;
        Ok(written)
    }
}

/// `access_right ::= structure { attribute_access: array attribute_access_item, method_access: array method_access_item }`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AccessRight<'a> {
    pub attribute_access: &'a [AttributeAccessItem<'a>],
    pub method_access: &'a [MethodAccessItem],
}

impl<'a> Encodable for AccessRight<'a> {
    /// Encode this structure (two nested arrays).
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        let mut written = buf.put_u8(2)?; // structure tag
        written += put_length(buf, 2)?;
        written += buf.put_u8(1)?; // attribute_access array tag
        written += put_length(buf, self.attribute_access.len())?;
        for item in self.attribute_access {
            written += item.put(buf)?;
        }
        written += buf.put_u8(1)?; // method_access array tag
        written += put_length(buf, self.method_access.len())?;
        for item in self.method_access {
            written += item.put(buf)?;
        }
        Ok(written)
    }
}

/// `object_list_element ::= structure { class_id: long-unsigned, version: unsigned, logical_name: octet-string, access_rights: access_right }`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ObjectListElement<'a> {
    pub class_id: ClassId,
    pub version: u8,
    pub logical_name: ObisCode,
    pub access_rights: AccessRight<'a>,
}

impl<'a> Encodable for ObjectListElement<'a> {
    /// Encode this structure.
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        let mut written = buf.put_u8(2)?; // structure tag
        written += put_length(buf, 4)?;
        written += Data::LongUnsigned(self.class_id.as_u16()).put(buf)?;
        written += Data::Unsigned(self.version).put(buf)?;
        written += Data::OctetString(&self.logical_name.bytes).put(buf)?;
        written += self.access_rights.put(buf)?;
        Ok(written)
    }
}

/// `object_list_type ::= array object_list_element`.
pub type ObjectList<'a> = Array<'a, ObjectListElement<'a>>;

/// Validates `object_list` (array of `object_list_element`).
#[derive(Debug)]
pub struct ObjectListValidator;

impl Validator for ObjectListValidator {
    fn validate(&self, data: &Data<'_>) -> Result<()> {
        let items = data
            .as_array()
            .ok_or(Error::Codec(cosempdu::Error::Message(
                "object_list must be an array",
            )))?;
        for item in items {
            validate_element(item).map_err(Error::from)?;
        }
        Ok(())
    }
}

/// Validates a single `object_list_element`.
fn validate_element(data: &Data<'_>) -> cosempdu::Result<()> {
    let fields = data.as_structure().ok_or(cosempdu::Error::Message(
        "object_list_element must be a structure",
    ))?;
    if fields.len() != 4 {
        return Err(cosempdu::Error::Message(
            "object_list_element must be a structure of four fields",
        ));
    }
    let raw = fields[0]
        .as_long_unsigned()
        .ok_or(cosempdu::Error::Message("field 0 must be a long-unsigned"))?;
    ClassId::from_u16(raw).ok_or(cosempdu::Error::Message("field 0 is not a known class_id"))?;
    fields[1]
        .as_unsigned()
        .ok_or(cosempdu::Error::Message("field 1 must be an unsigned"))?;
    let ln = fields[2]
        .as_octet_string()
        .ok_or(cosempdu::Error::Message("field 2 must be an octet-string"))?;
    if ln.len() != 6 {
        return Err(cosempdu::Error::Message(
            "logical_name must be exactly 6 bytes",
        ));
    }
    validate_access_right(&fields[3])
}

/// Validates an `access_right` structure.
fn validate_access_right(data: &Data<'_>) -> cosempdu::Result<()> {
    let fields = data
        .as_structure()
        .ok_or(cosempdu::Error::Message("access_right must be a structure"))?;
    if fields.len() != 2 {
        return Err(cosempdu::Error::Message(
            "access_right must be a structure of two fields",
        ));
    }
    let attribute_access = fields[0]
        .as_array()
        .ok_or(cosempdu::Error::Message("field 0 must be an array"))?;
    for item in attribute_access {
        validate_attribute_access_item(item)?;
    }
    let method_access = fields[1]
        .as_array()
        .ok_or(cosempdu::Error::Message("field 1 must be an array"))?;
    for item in method_access {
        validate_method_access_item(item)?;
    }
    Ok(())
}

/// Validates an `attribute_access_item` structure.
fn validate_attribute_access_item(data: &Data<'_>) -> cosempdu::Result<()> {
    let fields = data.as_structure().ok_or(cosempdu::Error::Message(
        "attribute_access_item must be a structure",
    ))?;
    if fields.len() != 3 {
        return Err(cosempdu::Error::Message(
            "attribute_access_item must be a structure of three fields",
        ));
    }
    fields[0]
        .as_integer()
        .ok_or(cosempdu::Error::Message("field 0 must be an integer"))?;
    fields[1]
        .as_enum()
        .and_then(AttributeAccessMode::from_u8)
        .ok_or(cosempdu::Error::Message(
            "field 1 must be a known attribute access_mode",
        ))?;
    match fields[2] {
        Data::NullData => Ok(()),
        Data::Array(items) => {
            for item in items {
                item.as_integer().ok_or(cosempdu::Error::Message(
                    "access_selectors array must contain integers",
                ))?;
            }
            Ok(())
        }
        _ => Err(cosempdu::Error::Message(
            "access_selectors must be null-data or an array of integers",
        )),
    }
}

/// Validates a `method_access_item` structure.
fn validate_method_access_item(data: &Data<'_>) -> cosempdu::Result<()> {
    let fields = data.as_structure().ok_or(cosempdu::Error::Message(
        "method_access_item must be a structure",
    ))?;
    if fields.len() != 2 {
        return Err(cosempdu::Error::Message(
            "method_access_item must be a structure of two fields",
        ));
    }
    fields[0]
        .as_integer()
        .ok_or(cosempdu::Error::Message("field 0 must be an integer"))?;
    fields[1]
        .as_enum()
        .and_then(MethodAccessMode::from_u8)
        .ok_or(cosempdu::Error::Message(
            "field 1 must be a known method access_mode",
        ))?;
    Ok(())
}

/// Static `object_list` validator (as a trait object).
pub const OBJECT_LIST_VALIDATOR: &dyn Validator = &ObjectListValidator;

/// `context_name_structure ::= structure { ... }` — the arc labels of the
/// application-context OBJECT IDENTIFIER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextNameStructure {
    pub joint_iso_ctt_element: u8,
    pub country_element: u8,
    pub country_name_element: u16,
    pub identified_organization_element: u8,
    pub dlms_ua_element: u8,
    pub application_context_element: u8,
    pub context_id_element: u8,
}

impl<'a> FromStructure<'a> for ContextNameStructure {
    fn from_structure(fields: &'a [Data<'a>]) -> cosempdu::Result<Self> {
        if fields.len() != 7 {
            return Err(cosempdu::Error::Message(
                "context_name_structure must be a structure of seven fields",
            ));
        }
        Ok(ContextNameStructure {
            joint_iso_ctt_element: fields[0]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 0 must be an unsigned"))?,
            country_element: fields[1]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 1 must be an unsigned"))?,
            country_name_element: fields[2]
                .as_long_unsigned()
                .ok_or(cosempdu::Error::Message("field 2 must be a long-unsigned"))?,
            identified_organization_element: fields[3]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 3 must be an unsigned"))?,
            dlms_ua_element: fields[4]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 4 must be an unsigned"))?,
            application_context_element: fields[5]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 5 must be an unsigned"))?,
            context_id_element: fields[6]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 6 must be an unsigned"))?,
        })
    }
}

impl Codec for ContextNameStructure {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::Structure(&[
            Data::Unsigned(self.joint_iso_ctt_element),
            Data::Unsigned(self.country_element),
            Data::LongUnsigned(self.country_name_element),
            Data::Unsigned(self.identified_organization_element),
            Data::Unsigned(self.dlms_ua_element),
            Data::Unsigned(self.application_context_element),
            Data::Unsigned(self.context_id_element),
        ])
        .put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        *self = data.recast::<ContextNameStructure>()?;
        Ok(())
    }
}

/// `context_name_type ::= CHOICE { context_name_structure [2], octet-string [9] }`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContextName<'a> {
    Structure(ContextNameStructure),
    OctetString(&'a [u8]),
}

impl<'a> ContextName<'a> {
    pub fn from_data(data: &'a Data<'a>) -> cosempdu::Result<Self> {
        match data {
            Data::Structure(fields) => Ok(ContextName::Structure(
                ContextNameStructure::from_structure(fields)?,
            )),
            Data::OctetString(bytes) => Ok(ContextName::OctetString(bytes)),
            _ => Err(cosempdu::Error::Message(
                "context_name must be a structure or octet-string",
            )),
        }
    }
}

/// Validates `context_name_type` (CHOICE).
#[derive(Debug)]
pub struct ContextNameValidator;

impl Validator for ContextNameValidator {
    fn validate(&self, data: &Data<'_>) -> Result<()> {
        ContextName::from_data(data)
            .map(|_| ())
            .map_err(Error::from)
    }
}

/// Static `context_name_type` validator (as a trait object).
pub const CONTEXT_NAME_VALIDATOR: &dyn Validator = &ContextNameValidator;

/// `mechanism_name_structure ::= structure { ... }` — the arc labels of the
/// authentication-mechanism OBJECT IDENTIFIER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MechanismNameStructure {
    pub joint_iso_ctt_element: u8,
    pub country_element: u8,
    pub country_name_element: u16,
    pub identified_organization_element: u8,
    pub dlms_ua_element: u8,
    pub authentication_mechanism_name_element: u8,
    pub mechanism_id_element: u8,
}

impl<'a> FromStructure<'a> for MechanismNameStructure {
    fn from_structure(fields: &'a [Data<'a>]) -> cosempdu::Result<Self> {
        if fields.len() != 7 {
            return Err(cosempdu::Error::Message(
                "mechanism_name_structure must be a structure of seven fields",
            ));
        }
        Ok(MechanismNameStructure {
            joint_iso_ctt_element: fields[0]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 0 must be an unsigned"))?,
            country_element: fields[1]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 1 must be an unsigned"))?,
            country_name_element: fields[2]
                .as_long_unsigned()
                .ok_or(cosempdu::Error::Message("field 2 must be a long-unsigned"))?,
            identified_organization_element: fields[3]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 3 must be an unsigned"))?,
            dlms_ua_element: fields[4]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 4 must be an unsigned"))?,
            authentication_mechanism_name_element: fields[5]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 5 must be an unsigned"))?,
            mechanism_id_element: fields[6]
                .as_unsigned()
                .ok_or(cosempdu::Error::Message("field 6 must be an unsigned"))?,
        })
    }
}

impl Codec for MechanismNameStructure {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::Structure(&[
            Data::Unsigned(self.joint_iso_ctt_element),
            Data::Unsigned(self.country_element),
            Data::LongUnsigned(self.country_name_element),
            Data::Unsigned(self.identified_organization_element),
            Data::Unsigned(self.dlms_ua_element),
            Data::Unsigned(self.authentication_mechanism_name_element),
            Data::Unsigned(self.mechanism_id_element),
        ])
        .put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        *self = data.recast::<MechanismNameStructure>()?;
        Ok(())
    }
}

/// `mechanism_name_type ::= CHOICE { mechanism_name_structure [2], octet-string [9] }`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MechanismName<'a> {
    Structure(MechanismNameStructure),
    OctetString(&'a [u8]),
}

impl<'a> MechanismName<'a> {
    pub fn from_data(data: &'a Data<'a>) -> cosempdu::Result<Self> {
        match data {
            Data::Structure(fields) => Ok(MechanismName::Structure(
                MechanismNameStructure::from_structure(fields)?,
            )),
            Data::OctetString(bytes) => Ok(MechanismName::OctetString(bytes)),
            _ => Err(cosempdu::Error::Message(
                "mechanism_name must be a structure or octet-string",
            )),
        }
    }
}

/// Validates `mechanism_name_type` (CHOICE).
#[derive(Debug)]
pub struct MechanismNameValidator;

impl Validator for MechanismNameValidator {
    fn validate(&self, data: &Data<'_>) -> Result<()> {
        MechanismName::from_data(data)
            .map(|_| ())
            .map_err(Error::from)
    }
}

/// Static `mechanism_name_type` validator (as a trait object).
pub const MECHANISM_NAME_VALIDATOR: &dyn Validator = &MechanismNameValidator;

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

    /// Key of the `secret` attribute.
    pub fn secret(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_SECRET)
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
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn class_id(&self) -> ClassId {
        ClassId::AssociationLn
    }

    fn version(&self) -> u8 {
        V1
    }

    fn obis(&self) -> ObisCode {
        self.obis
    }

    fn attributes(&self) -> &'static [AttributeInfo] {
        &[
            AttributeInfo {
                data_type: AttributeType::Validator(OBJECT_LIST_VALIDATOR),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Validator(ASSOCIATED_PARTNERS_VALIDATOR),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Dynamic,
            },
            AttributeInfo {
                data_type: AttributeType::Validator(CONTEXT_NAME_VALIDATOR),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Dynamic,
            },
            AttributeInfo {
                data_type: AttributeType::Validator(XDLMS_CONTEXT_INFO_VALIDATOR),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Dynamic,
            },
            AttributeInfo {
                data_type: AttributeType::Validator(MECHANISM_NAME_VALIDATOR),
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
                classifier: Classifier::Dynamic,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_descriptor() {
        let ln = AssociationLn::new(ObisCode::new(0, 0, 40, 0, 0, 255));
        assert_eq!((ln.class_id(), ln.version()), (ClassId::AssociationLn, V1));
        assert_eq!(ln.attributes().len(), 8);
        assert_eq!(ln.attr_key(1).map(|k| k.attribute_id), Some(1));
        assert_eq!(ln.attr_key(2).map(|k| k.attribute_id), Some(2));
        assert_eq!(ln.attr_key(9).map(|k| k.attribute_id), Some(9));
        assert_eq!(ln.attr_key(10), None);
    }

    #[test]
    fn object_list_validates_and_encodes() {
        let ln: ObisCode = "1.0.1.8.0.255".parse().unwrap();

        // Decoded form — hand-written validator.
        let attr_item_fields = [Data::Integer(2), Data::Enum(3), Data::NullData];
        let attr_item = Data::Structure(&attr_item_fields);
        let method_item_fields = [Data::Integer(1), Data::Enum(1)];
        let method_item = Data::Structure(&method_item_fields);
        let attr_array = [attr_item];
        let method_array = [method_item];
        let access_fields = [Data::Array(&attr_array), Data::Array(&method_array)];
        let access_right = Data::Structure(&access_fields);
        let element_fields = [
            Data::LongUnsigned(ClassId::Register.as_u16()),
            Data::Unsigned(0),
            Data::OctetString(&ln.bytes),
            access_right,
        ];
        let element = Data::Structure(&element_fields);
        let list = [element];
        assert!(OBJECT_LIST_VALIDATOR.validate(&Data::Array(&list)).is_ok());

        // Borrowed typed view — encoding (put).
        let attr_item = AttributeAccessItem {
            attribute_id: 2,
            access_mode: AttributeAccessMode::ReadAndWrite,
            access_selectors: AccessSelectors::Null,
        };
        let attr_array = [attr_item];
        let method_item = MethodAccessItem {
            method_id: 1,
            access_mode: MethodAccessMode::Access,
        };
        let method_array = [method_item];
        let access_right = AccessRight {
            attribute_access: &attr_array,
            method_access: &method_array,
        };
        let element = ObjectListElement {
            class_id: ClassId::Register,
            version: 0,
            logical_name: ln,
            access_rights: access_right,
        };
        let elements = [element];
        let object_list = ObjectList { items: &elements };

        let mut backing = [0u8; 64];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            object_list.put(&mut b).unwrap()
        };
        assert_eq!(
            &backing[..n],
            &[
                0x01, 0x01, // array {1}
                0x02, 0x04, // structure {4}
                0x12, 0x00, 0x03, // class_id long-unsigned 3
                0x11, 0x00, // version unsigned 0
                0x09, 0x06, 0x01, 0x00, 0x01, 0x08, 0x00, 0xFF, // logical_name
                0x02, 0x02, // access_rights structure {2}
                0x01, 0x01, // attribute_access array {1}
                0x02, 0x03, // attribute_access_item structure {3}
                0x0F, 0x02, // attribute_id integer 2
                0x16, 0x03, // access_mode enum 3
                0x00, // access_selectors null-data
                0x01, 0x01, // method_access array {1}
                0x02, 0x02, // method_access_item structure {2}
                0x0F, 0x01, // method_id integer 1
                0x16, 0x01, // access_mode enum 1
            ]
        );
    }

    #[test]
    fn context_name_and_mechanism_name() {
        let oct = [0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01];
        match ContextName::from_data(&Data::OctetString(&oct)).unwrap() {
            ContextName::OctetString(b) => assert_eq!(b, &oct[..]),
            other => panic!("expected octet-string, got {other:?}"),
        }

        let fields = [
            Data::Unsigned(2),
            Data::Unsigned(17),
            Data::LongUnsigned(756),
            Data::Unsigned(5),
            Data::Unsigned(8),
            Data::Unsigned(1),
            Data::Unsigned(1),
        ];
        let structure = Data::Structure(&fields);
        match ContextName::from_data(&structure).unwrap() {
            ContextName::Structure(s) => {
                assert_eq!(s.context_id_element, 1);
                assert_eq!(s.country_name_element, 756);
            }
            other => panic!("expected structure, got {other:?}"),
        }

        let mech_oct = [0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01];
        assert!(matches!(
            MechanismName::from_data(&Data::OctetString(&mech_oct)),
            Ok(MechanismName::OctetString(_))
        ));
        assert!(ContextName::from_data(&Data::NullData).is_err());
    }

    #[test]
    fn validators_accept_and_reject() {
        assert!(OBJECT_LIST_VALIDATOR.validate(&Data::NullData).is_err());

        let oct = [0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01];
        assert!(CONTEXT_NAME_VALIDATOR
            .validate(&Data::OctetString(&oct))
            .is_ok());
        assert!(CONTEXT_NAME_VALIDATOR.validate(&Data::NullData).is_err());
        assert!(MECHANISM_NAME_VALIDATOR
            .validate(&Data::OctetString(&oct))
            .is_ok());
        assert!(MECHANISM_NAME_VALIDATOR.validate(&Data::NullData).is_err());
    }
}
