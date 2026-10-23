//! COSEM interface class "Register activation" (class_id 6, version 0).

use cosempdu::axdr::put_length;
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::{Codec, Data, FromStructure};
use cosempdu::stream::StreamSink;

use crate::error::{Error, Result};
use crate::ic::{
    AttributeInfo, AttributeKey, AttributeType, ClassId, Classifier, CommonDataType,
    InterfaceClass, Validator, V0,
};
use crate::obis::ObisCode;

/// Attribute 2 — `register_assignment` (array of `object_definition`).
pub const ATTR_REGISTER_ASSIGNMENT: u8 = 2;
/// Attribute 3 — `mask_list` (array of `register_act_mask`).
pub const ATTR_MASK_LIST: u8 = 3;
/// Attribute 4 — `active_mask` (octet-string: a `mask_name` from `mask_list`).
pub const ATTR_ACTIVE_MASK: u8 = 4;

/// `object_definition ::= structure { class_id: long-unsigned, logical_name: octet-string }`.
///
/// One entry of `register_assignment`: identifies an assigned COSEM object by
/// its interface class and logical name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectDefinition {
    pub class_id: ClassId,
    pub logical_name: ObisCode,
}

impl<'a> FromStructure<'a> for ObjectDefinition {
    fn from_structure(fields: &'a [Data<'a>]) -> cosempdu::Result<Self> {
        if fields.len() != 2 {
            return Err(cosempdu::Error::Message(
                "object_definition must be a structure of two fields",
            ));
        }
        let raw = fields[0]
            .as_long_unsigned()
            .ok_or(cosempdu::Error::Message("field 0 must be a long-unsigned"))?;
        let class_id = ClassId::from_u16(raw)
            .ok_or(cosempdu::Error::Message("field 0 is not a known class_id"))?;
        let ln = fields[1]
            .as_octet_string()
            .ok_or(cosempdu::Error::Message("field 1 must be an octet-string"))?;
        if ln.len() != 6 {
            return Err(cosempdu::Error::Message(
                "logical_name must be exactly 6 bytes",
            ));
        }
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(ln);
        Ok(ObjectDefinition {
            class_id,
            logical_name: ObisCode::from_bytes(bytes),
        })
    }
}

impl ObjectDefinition {
    /// Placeholder for uninitialised slots (logical name `0.0.0.0.0.0`).
    pub const EMPTY: ObjectDefinition = ObjectDefinition {
        class_id: ClassId::Data,
        logical_name: ObisCode::new(0, 0, 0, 0, 0, 0),
    };
}

impl Default for ObjectDefinition {
    fn default() -> Self {
        ObjectDefinition::EMPTY
    }
}

impl Codec for ObjectDefinition {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        let fields = [
            Data::LongUnsigned(self.class_id.as_u16()),
            Data::OctetString(&self.logical_name.bytes),
        ];
        Data::Structure(&fields).put(buf)
    }

    fn assign(&mut self, d: &Data<'_>) -> cosempdu::Result<()> {
        *self = d.recast::<ObjectDefinition>()?;
        Ok(())
    }
}

/// `register_act_mask ::= structure { mask_name: octet-string, index_list: index_array }`.
///
/// One entry of `mask_list`: a named tariff mask referencing (by 1-based index)
/// the objects in `register_assignment`. `mask_name` borrows from the decoded
/// buffer; `index_list` is the borrowed `index_array ::= array unsigned`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RegisterActMask<'a> {
    pub mask_name: &'a [u8],
    pub index_list: &'a [Data<'a>],
}

impl<'a> FromStructure<'a> for RegisterActMask<'a> {
    fn from_structure(fields: &'a [Data<'a>]) -> cosempdu::Result<Self> {
        if fields.len() != 2 {
            return Err(cosempdu::Error::Message(
                "register_act_mask must be a structure of two fields",
            ));
        }
        let mask_name = fields[0]
            .as_octet_string()
            .ok_or(cosempdu::Error::Message("field 0 must be an octet-string"))?;
        let index_list = fields[1]
            .as_array()
            .ok_or(cosempdu::Error::Message("field 1 must be an array"))?;
        for entry in index_list {
            if entry.as_unsigned().is_none() {
                return Err(cosempdu::Error::Message(
                    "index_list entries must be unsigned",
                ));
            }
        }
        Ok(RegisterActMask {
            mask_name,
            index_list,
        })
    }
}

/// Validates `register_assignment` (array of `object_definition`).
#[derive(Debug)]
pub struct RegisterAssignmentValidator;

impl Validator for RegisterAssignmentValidator {
    fn validate(&self, data: &Data<'_>) -> Result<()> {
        let items = data.as_array().ok_or(Error::Codec(cosempdu::Error::Message(
            "register_assignment must be an array",
        )))?;
        for item in items {
            item.recast::<ObjectDefinition>().map_err(Error::from)?;
        }
        Ok(())
    }
}

/// Static `register_assignment` validator (as a trait object).
pub const REGISTER_ASSIGNMENT_VALIDATOR: &dyn Validator = &RegisterAssignmentValidator;

/// Validates `mask_list` (array of `register_act_mask`).
#[derive(Debug)]
pub struct MaskListValidator;

impl Validator for MaskListValidator {
    fn validate(&self, data: &Data<'_>) -> Result<()> {
        let items = data.as_array().ok_or(Error::Codec(cosempdu::Error::Message(
            "mask_list must be an array",
        )))?;
        for item in items {
            item.recast::<RegisterActMask<'_>>().map_err(Error::from)?;
        }
        Ok(())
    }
}

/// Static `mask_list` validator (as a trait object).
pub const MASK_LIST_VALIDATOR: &dyn Validator = &MaskListValidator;

/// COSEM interface class "Register activation" (class_id 6): a static object descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterActivation {
    pub obis: ObisCode,
}

impl RegisterActivation {
    pub const fn new(obis: ObisCode) -> Self {
        RegisterActivation { obis }
    }

    /// Key of the `register_assignment` attribute.
    pub fn register_assignment(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_REGISTER_ASSIGNMENT)
    }

    /// Key of the `mask_list` attribute.
    pub fn mask_list(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_MASK_LIST)
    }

    /// Key of the `active_mask` attribute.
    pub fn active_mask(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_ACTIVE_MASK)
    }
}

impl InterfaceClass for RegisterActivation {
    fn class_id(&self) -> ClassId {
        ClassId::RegisterActivation
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
                data_type: AttributeType::Validator(REGISTER_ASSIGNMENT_VALIDATOR),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Validator(MASK_LIST_VALIDATOR),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Static,
            },
            AttributeInfo {
                data_type: AttributeType::Common(CommonDataType::OctetString),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Dynamic,
            },
        ]
    }
}

/// Concrete, fixed-capacity value for `register_assignment` (`array object_definition`).
///
/// The array holds exactly `N` assigned objects (no separate length field); it can
/// be filled via [`Codec::assign`] or streamed into through [`Codec::stream_sink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterAssignmentValue<const N: usize>(pub [ObjectDefinition; N]);

impl<const N: usize> Default for RegisterAssignmentValue<N> {
    fn default() -> Self {
        RegisterAssignmentValue([ObjectDefinition::EMPTY; N])
    }
}

impl<const N: usize> Codec for RegisterAssignmentValue<N> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        let mut written = buf.put_u8(1).map_err(cosempdu::Error::from)?; // array tag
        written += put_length(buf, N)?;
        for od in &self.0 {
            written += od.put(buf)?;
        }
        Ok(written)
    }

    fn assign(&mut self, d: &Data<'_>) -> cosempdu::Result<()> {
        let items = d
            .as_array()
            .ok_or(cosempdu::Error::UnexpectedTag { name: "array", actual: d.tag() })?;
        if items.len() != N {
            return Err(cosempdu::Error::Message(
                "register_assignment has wrong entry count",
            ));
        }
        for (i, item) in items.iter().enumerate() {
            self.0[i].assign(item)?;
        }
        Ok(())
    }

    fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
        Some(self)
    }
}

impl<const N: usize> StreamSink for RegisterAssignmentValue<N> {
    fn composite_begin(&mut self, tag: u8, count: usize) -> cosempdu::Result<()> {
        match tag {
            1 => {
                if count != N {
                    return Err(cosempdu::Error::Message(
                        "register_assignment has wrong entry count",
                    ));
                }
                Ok(())
            }
            2 => {
                if count != 2 {
                    return Err(cosempdu::Error::Message(
                        "object_definition must be a structure of 2 fields",
                    ));
                }
                Ok(())
            }
            _ => Err(cosempdu::Error::UnexpectedComposite),
        }
    }

    fn scalar(&mut self, tag: u8, bytes: &[u8], index: usize) -> cosempdu::Result<()> {
        if tag != 18 || bytes.len() != 2 {
            return Err(cosempdu::Error::Message(
                "class_id must be a long-unsigned",
            ));
        }
        let raw = u16::from_be_bytes([bytes[0], bytes[1]]);
        let class_id = ClassId::from_u16(raw)
            .ok_or(cosempdu::Error::Message("unknown class_id"))?;
        self.0[index].class_id = class_id;
        Ok(())
    }

    fn blob_begin(&mut self, tag: u8, len: usize) -> cosempdu::Result<()> {
        if tag != 9 || len != 6 {
            return Err(cosempdu::Error::Message(
                "logical_name must be a 6-byte octet-string",
            ));
        }
        Ok(())
    }

    fn blob_write(&mut self, bytes: &[u8], index: usize, offset: usize) -> cosempdu::Result<()> {
        let end = offset + bytes.len();
        if end > 6 {
            return Err(cosempdu::Error::InputTooLarge { len: end, max: 6 });
        }
        self.0[index].logical_name.bytes[offset..end].copy_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_definition_from_structure() {
        let ln: ObisCode = "1.0.1.8.0.255".parse().unwrap();
        let fields = [
            Data::LongUnsigned(ClassId::Register.as_u16()),
            Data::OctetString(&ln.bytes),
        ];
        let od = Data::Structure(&fields).recast::<ObjectDefinition>().unwrap();
        assert_eq!(od.class_id, ClassId::Register);
        assert_eq!(od.logical_name, ln);
    }

    #[test]
    fn object_definition_rejects_bad_shape() {
        // Too few fields.
        let bad = Data::Structure(&[Data::LongUnsigned(3)]);
        assert!(bad.recast::<ObjectDefinition>().is_err());

        // logical_name must be exactly 6 bytes.
        let bad_ln = Data::Structure(&[
            Data::LongUnsigned(3),
            Data::OctetString(&[1, 2, 3]),
        ]);
        assert!(bad_ln.recast::<ObjectDefinition>().is_err());

        // class_id must be a known interface class.
        let unknown = Data::Structure(&[
            Data::LongUnsigned(0xFFFF),
            Data::OctetString(&[0, 0, 96, 1, 0, 255]),
        ]);
        assert!(unknown.recast::<ObjectDefinition>().is_err());
    }

    #[test]
    fn register_act_mask_from_structure() {
        let entries = [Data::Unsigned(1), Data::Unsigned(3), Data::Unsigned(4)];
        let fields = [Data::OctetString(b"day"), Data::Array(&entries)];
        let mask = Data::Structure(&fields).recast::<RegisterActMask<'_>>().unwrap();
        assert_eq!(mask.mask_name, b"day");
        assert_eq!(mask.index_list.len(), 3);
        assert_eq!(mask.index_list[0].as_unsigned(), Some(1));
        assert_eq!(mask.index_list[2].as_unsigned(), Some(4));
    }

    #[test]
    fn validators_accept_and_reject() {
        let ln: ObisCode = "1.0.1.8.0.255".parse().unwrap();
        let od_fields = [
            Data::LongUnsigned(ClassId::Register.as_u16()),
            Data::OctetString(&ln.bytes),
        ];
        let od = Data::Structure(&od_fields);
        let assignments = [od];
        assert!(REGISTER_ASSIGNMENT_VALIDATOR
            .validate(&Data::Array(&assignments))
            .is_ok());

        let entries = [Data::Unsigned(1)];
        let mask_fields = [Data::OctetString(b"day"), Data::Array(&entries)];
        let mask = Data::Structure(&mask_fields);
        let masks = [mask];
        assert!(MASK_LIST_VALIDATOR
            .validate(&Data::Array(&masks))
            .is_ok());

        // Top level must be an array, not a structure.
        let not_array = [od];
        assert!(REGISTER_ASSIGNMENT_VALIDATOR
            .validate(&Data::Structure(&not_array))
            .is_err());

        // index_list entries must be unsigned.
        let bad_entries = [Data::Enum(0)];
        let bad_mask_fields = [Data::OctetString(b"day"), Data::Array(&bad_entries)];
        let bad_mask = Data::Structure(&bad_mask_fields);
        let bad_masks = [bad_mask];
        assert!(MASK_LIST_VALIDATOR
            .validate(&Data::Array(&bad_masks))
            .is_err());
    }

    #[test]
    fn class_descriptor() {
        let ra = RegisterActivation::new("0.0.96.1.0.255".parse().unwrap());
        assert_eq!(
            (ra.class_id(), ra.version()),
            (ClassId::RegisterActivation, V0)
        );
        assert_eq!(ra.obis().to_string(), "0.0.96.1.0.255");
        assert_eq!(ra.attributes().len(), 3);
        assert_eq!(ra.attr_key(2).map(|k| k.attribute_id), Some(2));
        assert_eq!(ra.attr_key(3).map(|k| k.attribute_id), Some(3));
        assert_eq!(ra.attr_key(4).map(|k| k.attribute_id), Some(4));
        assert_eq!(ra.attr_key(5), None);
    }
}

