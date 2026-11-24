//! COSEM interface class "Association LN" (class_id 15, version 1).

use cosempdu::acse::ApplicationContextName;
use cosempdu::axdr::put_length;
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::{Codec, Data, Encodable, FromStructure};

use crate::common_data_types::Array;
use crate::error::{Error, Result};
use crate::ic::{
    AttributeInfo, AttributeKey, AttributeType, ClassId, Classifier, CommonDataType,
    InterfaceClass, MethodKey, Validator, ASSOCIATED_PARTNERS_VALIDATOR, V1,
    XDLMS_CONTEXT_INFO_VALIDATOR,
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
pub const ATTR_LOGICAL_NAME: i8 = 1;
/// Attribute 2 — `object_list` (`object_list_type`).
pub const ATTR_OBJECT_LIST: i8 = 2;
/// Attribute 3 — `associated_partners_id` (`associated_partners_type`).
pub const ATTR_ASSOCIATED_PARTNERS_ID: i8 = 3;
/// Attribute 4 — `application_context_name` (`context_name_type`).
pub const ATTR_APPLICATION_CONTEXT_NAME: i8 = 4;
/// Attribute 5 — `xDLMS_context_info` (`xDLMS_context_type`).
pub const ATTR_XDLMS_CONTEXT_INFO: i8 = 5;
/// Attribute 6 — `authentication_mechanism_name` (`mechanism_name_type`).
pub const ATTR_AUTHENTICATION_MECHANISM_NAME: i8 = 6;
/// Attribute 7 — `secret` (octet-string).
pub const ATTR_SECRET: i8 = 7;
/// Attribute 8 — `association_status` (enum).
pub const ATTR_ASSOCIATION_STATUS: i8 = 8;
/// Attribute 9 — `security_setup_reference` (octet-string).
pub const ATTR_SECURITY_SETUP_REFERENCE: i8 = 9;

/// Method 1 — `reply_to_HLS_authentication` (data).
pub const METHOD_REPLY_TO_HLS_AUTHENTICATION: i8 = 1;
/// Method 2 — `change_HLS_secret` (data).
pub const METHOD_CHANGE_HLS_SECRET: i8 = 2;
/// Method 3 — `add_object` (data).
pub const METHOD_ADD_OBJECT: i8 = 3;
/// Method 4 — `remove_object` (data).
pub const METHOD_REMOVE_OBJECT: i8 = 4;

/// `association_status` (attribute 8): current status of the association
/// modelled by the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AssociationStatus {
    /// (0) non-associated.
    NonAssociated = 0,
    /// (1) association-pending.
    AssociationPending = 1,
    /// (2) associated.
    Associated = 2,
}

impl AssociationStatus {
    /// Raw enum value as encoded in the PDU.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decode from the raw enum value; `None` for unknown values.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NonAssociated),
            1 => Some(Self::AssociationPending),
            2 => Some(Self::Associated),
            _ => None,
        }
    }
}

impl Codec for AssociationStatus {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::Enum(self.as_u8()).put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        let value = data
            .as_enum()
            .ok_or(cosempdu::Error::Message("association-status must be enum"))?;
        *self = AssociationStatus::from_u8(value)
            .ok_or(cosempdu::Error::Message("unknown association-status value"))?;
        Ok(())
    }
}

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

// ---------------------------------------------------------------------------
// Streaming `object_list` encoder (Association LN v1)
// ---------------------------------------------------------------------------

/// Byte sink for the streaming `object_list` encoder.
pub trait ObjectListSink {
    fn write(&mut self, bytes: &[u8]) -> cosempdu::Result<()>;
}

/// Object metadata for one `object_list_element`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectListElementInfo {
    pub class_id: ClassId,
    pub version: u8,
    pub logical_name: ObisCode,
}

/// Source of `object_list` content for Association LN v1.
///
/// The encoder below owns the A-XDR layout (tags, field order, array counts);
/// the source only supplies object metadata and the access entries.
pub trait ObjectListSource {
    fn object_count(&self) -> usize;
    fn element(&self, index: usize) -> ObjectListElementInfo;
    fn attribute_count(&self, index: usize) -> usize;
    fn attribute(&self, index: usize, item: usize) -> (i8, AttributeAccessMode);
    fn method_count(&self, index: usize) -> usize;
    fn method(&self, index: usize, item: usize) -> (i8, MethodAccessMode);
}

/// Methods advertised in `object_list` (Association LN v1).
pub const OBJECT_LIST_METHODS: [(i8, MethodAccessMode); 2] = [
    (METHOD_REPLY_TO_HLS_AUTHENTICATION, MethodAccessMode::Access),
    (
        METHOD_CHANGE_HLS_SECRET,
        MethodAccessMode::AuthenticatedAccess,
    ),
];

fn put_sink_length<S: ObjectListSink>(sink: &mut S, value: usize) -> cosempdu::Result<()> {
    if value <= 0x7F {
        return sink.write(&[value as u8]);
    }
    let bits = 64 - (value as u64).leading_zeros();
    let num_bytes = ((bits + 7) / 8) as usize;
    sink.write(&[0x80 | num_bytes as u8])?;
    let be = (value as u64).to_be_bytes();
    sink.write(&be[be.len() - num_bytes..])
}

/// Stream `object_list ::= array object_list_element` (Association LN v1) into
/// `sink`. The exact A-XDR tags/field order live here (version-dependent).
pub fn write_object_list<S: ObjectListSink, P: ObjectListSource>(
    sink: &mut S,
    source: &P,
) -> cosempdu::Result<()> {
    // array object_list_element
    sink.write(&[0x01])?;
    put_sink_length(sink, source.object_count())?;

    for i in 0..source.object_count() {
        let info = source.element(i);
        let attr_count = source.attribute_count(i);
        let method_count = source.method_count(i);

        // object_list_element ::= structure { class_id, version, logical_name, access_rights }
        sink.write(&[0x02])?;
        put_sink_length(sink, 4)?;
        sink.write(&[0x12])?; // long-unsigned
        sink.write(&info.class_id.as_u16().to_be_bytes())?;
        sink.write(&[0x11, info.version])?; // unsigned
        sink.write(&[0x09])?; // octet-string
        put_sink_length(sink, info.logical_name.bytes.len())?;
        sink.write(&info.logical_name.bytes)?;

        // access_right ::= structure { attribute_access, method_access }
        sink.write(&[0x02])?;
        put_sink_length(sink, 2)?;

        // attribute_access ::= array attribute_access_item
        sink.write(&[0x01])?;
        put_sink_length(sink, attr_count)?;
        for j in 0..attr_count {
            let (id, mode) = source.attribute(i, j);
            // attribute_access_item ::= structure { attribute_id, access_mode, access_selectors }
            sink.write(&[0x02])?;
            put_sink_length(sink, 3)?;
            sink.write(&[0x0F, id.to_be_bytes()[0]])?; // integer (Integer8)
            sink.write(&[0x16, mode as u8])?; // enum
            sink.write(&[0x00])?; // access_selectors: null-data
        }

        // method_access ::= array method_access_item
        sink.write(&[0x01])?;
        put_sink_length(sink, method_count)?;
        for j in 0..method_count {
            let (id, mode) = source.method(i, j);
            // method_access_item ::= structure { method_id, access_mode }
            sink.write(&[0x02])?;
            put_sink_length(sink, 2)?;
            sink.write(&[0x0F, id.to_be_bytes()[0]])?; // integer (Integer8)
            sink.write(&[0x16, mode as u8])?; // enum
        }
    }
    Ok(())
}

impl AssociationLn {
    /// Methods advertised in `object_list` (Association LN v1).
    pub const fn object_list_methods() -> &'static [(i8, MethodAccessMode)] {
        &OBJECT_LIST_METHODS
    }
}

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

impl ContextNameStructure {
    /// Build the `context_name_structure` from an ACSE application-context name
    /// (`{ 2 16 756 5 8 1 X }`).
    pub fn from_application_context(app: ApplicationContextName) -> Self {
        let a = app.to_arcs();
        ContextNameStructure {
            joint_iso_ctt_element: a[0] as u8,
            country_element: a[1] as u8,
            country_name_element: a[2] as u16,
            identified_organization_element: a[3] as u8,
            dlms_ua_element: a[4] as u8,
            application_context_element: a[5] as u8,
            context_id_element: a[6] as u8,
        }
    }
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
/// authentication-mechanism OBJECT IDENTIFIER. The first six arcs are fixed by
/// DLMS/COSEM (`{ 2 16 756 5 8 2 }`); only the mechanism id varies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MechanismNameStructure {
    /// The mechanism id (the last OID arc): `0` — lowest level security,
    /// `1` — LLS, `2`…`7` — HLS variants.
    pub mechanism_id: u8,
}

impl MechanismNameStructure {
    /// `{ 2 16 756 5 8 2 <mechanism_id> }` for an authentication mechanism id.
    pub const fn new(mechanism_id: u8) -> Self {
        Self { mechanism_id }
    }
}

impl<'a> FromStructure<'a> for MechanismNameStructure {
    fn from_structure(fields: &'a [Data<'a>]) -> cosempdu::Result<Self> {
        if fields.len() != 7 {
            return Err(cosempdu::Error::Message(
                "mechanism_name_structure must be a structure of seven fields",
            ));
        }
        // `{ 2 16 756 5 8 2 <id> }`
        let fixed = [
            fields[0].as_unsigned(),
            fields[1].as_unsigned(),
            fields[3].as_unsigned(),
            fields[4].as_unsigned(),
            fields[5].as_unsigned(),
        ];
        if fixed != [Some(2), Some(16), Some(5), Some(8), Some(2)]
            || fields[2].as_long_unsigned() != Some(756)
        {
            return Err(cosempdu::Error::Message(
                "mechanism_name_structure is not a DLMS mechanism name",
            ));
        }
        Ok(Self::new(fields[6].as_unsigned().ok_or(
            cosempdu::Error::Message("field 6 must be an unsigned"),
        )?))
    }
}

impl Codec for MechanismNameStructure {
    fn authentication_mechanism(&self) -> Option<u8> {
        Some(self.mechanism_id)
    }

    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::Structure(&[
            Data::Unsigned(2),
            Data::Unsigned(16),
            Data::LongUnsigned(756),
            Data::Unsigned(5),
            Data::Unsigned(8),
            Data::Unsigned(2),
            Data::Unsigned(self.mechanism_id),
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
    pub const fn object_list(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_OBJECT_LIST)
    }

    /// Key of the `associated_partners_id` attribute.
    pub const fn associated_partners_id(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_ASSOCIATED_PARTNERS_ID)
    }

    /// Key of the `application_context_name` attribute.
    pub const fn application_context_name(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_APPLICATION_CONTEXT_NAME)
    }

    /// Key of the `xDLMS_context_info` attribute.
    pub const fn xdlms_context_info(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_XDLMS_CONTEXT_INFO)
    }

    /// Key of the `authentication_mechanism_name` attribute.
    pub const fn authentication_mechanism_name(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_AUTHENTICATION_MECHANISM_NAME)
    }

    /// Key of the `secret` attribute.
    pub const fn secret(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_SECRET)
    }

    /// Key of the `association_status` attribute.
    pub const fn association_status(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_ASSOCIATION_STATUS)
    }

    /// Key of the `security_setup_reference` attribute.
    pub const fn security_setup_reference(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_SECURITY_SETUP_REFERENCE)
    }

    /// Key of the `reply_to_HLS_authentication` method.
    pub const fn reply_to_hls_authentication(&self) -> MethodKey {
        MethodKey::new(self.obis, METHOD_REPLY_TO_HLS_AUTHENTICATION)
    }

    /// Key of the `change_HLS_secret` method.
    pub const fn change_hls_secret(&self) -> MethodKey {
        MethodKey::new(self.obis, METHOD_CHANGE_HLS_SECRET)
    }

    /// Key of the `add_object` method.
    pub const fn add_object(&self) -> MethodKey {
        MethodKey::new(self.obis, METHOD_ADD_OBJECT)
    }

    /// Key of the `remove_object` method.
    pub const fn remove_object(&self) -> MethodKey {
        MethodKey::new(self.obis, METHOD_REMOVE_OBJECT)
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
    fn streaming_object_list_matches_encodable() {
        struct Sink {
            buf: [u8; 256],
            len: usize,
        }
        impl ObjectListSink for Sink {
            fn write(&mut self, bytes: &[u8]) -> cosempdu::Result<()> {
                self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
                self.len += bytes.len();
                Ok(())
            }
        }

        struct Src;
        impl ObjectListSource for Src {
            fn object_count(&self) -> usize {
                1
            }
            fn element(&self, _: usize) -> ObjectListElementInfo {
                ObjectListElementInfo {
                    class_id: ClassId::AssociationLn,
                    version: V1,
                    logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
                }
            }
            fn attribute_count(&self, _: usize) -> usize {
                2
            }
            fn attribute(&self, _: usize, item: usize) -> (i8, AttributeAccessMode) {
                match item {
                    0 => (1, AttributeAccessMode::ReadOnly),
                    _ => (2, AttributeAccessMode::ReadAndWrite),
                }
            }
            fn method_count(&self, _: usize) -> usize {
                1
            }
            fn method(&self, _: usize, _: usize) -> (i8, MethodAccessMode) {
                (METHOD_REPLY_TO_HLS_AUTHENTICATION, MethodAccessMode::Access)
            }
        }

        let mut sink = Sink {
            buf: [0u8; 256],
            len: 0,
        };
        write_object_list(&mut sink, &Src).unwrap();

        // Reference: `object_list` of one element via the canonical `Encodable`.
        let attrs = [
            AttributeAccessItem {
                attribute_id: 1,
                access_mode: AttributeAccessMode::ReadOnly,
                access_selectors: AccessSelectors::Null,
            },
            AttributeAccessItem {
                attribute_id: 2,
                access_mode: AttributeAccessMode::ReadAndWrite,
                access_selectors: AccessSelectors::Null,
            },
        ];
        let methods = [MethodAccessItem {
            method_id: METHOD_REPLY_TO_HLS_AUTHENTICATION,
            access_mode: MethodAccessMode::Access,
        }];
        let element = ObjectListElement {
            class_id: ClassId::AssociationLn,
            version: V1,
            logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
            access_rights: AccessRight {
                attribute_access: &attrs,
                method_access: &methods,
            },
        };

        let mut reference = [0u8; 256];
        let n = {
            let mut b = ByteBuffer::new(&mut reference);
            b.put_u8(0x01).unwrap(); // array
            put_length(&mut b, 1).unwrap();
            element.put(&mut b).unwrap();
            b.pos()
        };
        assert_eq!(&sink.buf[..sink.len], &reference[..n]);
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
    fn attribute_keys_are_const() {
        const OBIS: ObisCode = ObisCode::new(0, 0, 40, 0, 1, 255);
        const LN: AssociationLn = AssociationLn::new(OBIS);
        const KEY: AttributeKey = LN.object_list();
        assert_eq!(KEY, AttributeKey::new(OBIS, ATTR_OBJECT_LIST));

        const METHOD: MethodKey = LN.change_hls_secret();
        assert_eq!(METHOD, MethodKey::new(OBIS, METHOD_CHANGE_HLS_SECRET));
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
    fn mechanism_name_structure_from_mechanism_id() {
        let mech = MechanismNameStructure::new(1); // LLS
        assert_eq!(mech.mechanism_id, 1);

        let mut bytes = [0u8; 32];
        let n = {
            let mut b = ByteBuffer::new(&mut bytes);
            mech.put(&mut b).unwrap()
        };
        assert_eq!(
            &bytes[..n],
            &[
                0x02, 0x07, // structure (7)
                0x11, 0x02, // joint-iso-ctt (2)
                0x11, 0x10, // country (16)
                0x12, 0x02, 0xF4, // country-name (756)
                0x11, 0x05, // identified-organization (5)
                0x11, 0x08, // dlms-ua (8)
                0x11, 0x02, // authentication-mechanism-name (2)
                0x11, 0x01, // mechanism-id (1)
            ]
        );
        assert_eq!(mech.authentication_mechanism(), Some(1));

        // A structure with non-DLMS arcs is not a mechanism name.
        let fields = [
            Data::Unsigned(2),
            Data::Unsigned(17),
            Data::LongUnsigned(756),
            Data::Unsigned(5),
            Data::Unsigned(8),
            Data::Unsigned(2),
            Data::Unsigned(1),
        ];
        assert!(MechanismName::from_data(&Data::Structure(&fields)).is_err());
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
