//! COSEM interface classes (DLMS UA 1000-1 Ed. 14, clause 7).
//!
//! Each concrete class is a lightweight, static *object descriptor*: it carries
//! its OBIS code ([`ObisCode`]) and identifies the interface class it belongs to
//! ([`ClassId`], version) plus the reference info of its attributes
//! ([`AttributeInfo`]): value type (with validation), bounds, default and
//! classifier. Attribute *values* are stored per-attribute by the server.

pub mod association_ln;
pub mod association_sn;
pub mod clock;
pub mod data;
pub mod extended_register;
pub mod register;
pub mod register_activation;

use cosempdu::buffer::ByteBuffer;
use cosempdu::data::{Codec, Data, FromStructure};
use cosempdu::stream::StreamSink;

use crate::error::{Error, Result};
use crate::obis::ObisCode;

pub use association_ln::AssociationLn;
pub use association_sn::AssociationSn;
pub use clock::Clock;
pub use data::DataObject;
pub use extended_register::ExtendedRegister;
pub use register::{Register, ScalUnit, ScalUnitValidator, SCAL_UNIT_VALIDATOR};
pub use register_activation::{
    MaskListValidator, ObjectDefinition, RegisterActMask, RegisterActivation,
    RegisterAssignmentValidator, RegisterAssignmentValue,
    MASK_LIST_VALIDATOR, REGISTER_ASSIGNMENT_VALIDATOR,
};

/// COSEM interface class identifiers (clause 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ClassId {
    Data = 1,
    Register = 3,
    ExtendedRegister = 4,
    DemandRegister = 5,
    RegisterActivation = 6,
    ProfileGeneric = 7,
    Clock = 8,
    ScriptTable = 9,
    Schedule = 10,
    SpecialDaysTable = 11,
    AssociationSn = 12,
    AssociationLn = 15,
    SapAssignment = 17,
    ImageTransfer = 18,
    IecLocalPortSetup = 19,
    ActivityCalendar = 20,
    RegisterMonitor = 21,
    SingleActionSchedule = 22,
    IecHdlcSetup = 23,
    IecTwistedPairSetup = 24,
    MbusSlavePortSetup = 25,
    UtilityTables = 26,
    ModemConfiguration = 27,
    AutoAnswer = 28,
    AutoConnect = 29,
    PushSetup = 40,
    TcpUdpSetup = 41,
    Ipv4Setup = 42,
    MacAddressSetup = 43,
    PppSetup = 44,
    GprsSetup = 45,
    GsmDiagnostic = 46,
    LteMonitoring = 47,
    RegisterTable = 61,
    CompactData = 62,
    StatusMapping = 63,
    SecuritySetup = 64,
    DisconnectControl = 70,
    Limiter = 71,
    MbusClient = 72,
    MbusMasterPortSetup = 73,
}

impl ClassId {
    /// The numeric class identifier.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Parse a numeric class identifier.
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            1 => ClassId::Data,
            3 => ClassId::Register,
            4 => ClassId::ExtendedRegister,
            5 => ClassId::DemandRegister,
            6 => ClassId::RegisterActivation,
            7 => ClassId::ProfileGeneric,
            8 => ClassId::Clock,
            9 => ClassId::ScriptTable,
            10 => ClassId::Schedule,
            11 => ClassId::SpecialDaysTable,
            12 => ClassId::AssociationSn,
            15 => ClassId::AssociationLn,
            17 => ClassId::SapAssignment,
            18 => ClassId::ImageTransfer,
            19 => ClassId::IecLocalPortSetup,
            20 => ClassId::ActivityCalendar,
            21 => ClassId::RegisterMonitor,
            22 => ClassId::SingleActionSchedule,
            23 => ClassId::IecHdlcSetup,
            24 => ClassId::IecTwistedPairSetup,
            25 => ClassId::MbusSlavePortSetup,
            26 => ClassId::UtilityTables,
            27 => ClassId::ModemConfiguration,
            28 => ClassId::AutoAnswer,
            29 => ClassId::AutoConnect,
            40 => ClassId::PushSetup,
            41 => ClassId::TcpUdpSetup,
            42 => ClassId::Ipv4Setup,
            43 => ClassId::MacAddressSetup,
            44 => ClassId::PppSetup,
            45 => ClassId::GprsSetup,
            46 => ClassId::GsmDiagnostic,
            47 => ClassId::LteMonitoring,
            61 => ClassId::RegisterTable,
            62 => ClassId::CompactData,
            63 => ClassId::StatusMapping,
            64 => ClassId::SecuritySetup,
            70 => ClassId::DisconnectControl,
            71 => ClassId::Limiter,
            72 => ClassId::MbusClient,
            73 => ClassId::MbusMasterPortSetup,
            _ => return None,
        })
    }
}

/// Interface class version numbers (Blue Book Ed. 14).
///
/// Version is an open-ended `u8`; these named constants cover the range used
/// by the concrete classes in this crate (0..5).
pub const V0: u8 = 0;
pub const V1: u8 = 1;
pub const V2: u8 = 2;
pub const V3: u8 = 3;
pub const V4: u8 = 4;
pub const V5: u8 = 5;

/// Key of a single attribute: the object's OBIS code + attribute id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttributeKey {
    pub obis: ObisCode,
    pub attribute_id: u8,
}

impl AttributeKey {
    pub const fn new(obis: ObisCode, attribute_id: u8) -> Self {
        AttributeKey { obis, attribute_id }
    }
}

/// COSEM common data type (values coincide with the A-XDR implicit tags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommonDataType {
    NullData = 0,
    Array = 1,
    Structure = 2,
    Boolean = 3,
    BitString = 4,
    DoubleLong = 5,
    DoubleLongUnsigned = 6,
    OctetString = 9,
    VisibleString = 10,
    Utf8String = 12,
    Bcd = 13,
    Integer = 15,
    Long = 16,
    Unsigned = 17,
    LongUnsigned = 18,
    CompactArray = 19,
    Long64 = 20,
    Long64Unsigned = 21,
    Enum = 22,
    Float32 = 23,
    Float64 = 24,
    DateTime = 25,
    Date = 26,
    Time = 27,
    DontCare = 255,
}

impl CommonDataType {
    /// The A-XDR tag number of this common data type.
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// Tags of the `simple-data-type` CHOICE (the `value` of Register / Extended register).
pub const SIMPLE_DATA_TAGS: &'static [u8] =
    &[0, 4, 5, 6, 9, 10, 12, 15, 16, 17, 18, 20, 21, 22, 23, 24];

/// Validates a decoded [`Data`] value against an attribute's value type.
pub trait Validator: Sync + core::fmt::Debug {
    fn validate(&self, data: &Data<'_>) -> Result<()>;
}

/// The value type of an attribute (with validation logic).
#[derive(Debug, Clone, Copy)]
pub enum AttributeType {
    /// Simple common type — validated by a single A-XDR tag.
    Common(CommonDataType),
    /// A CHOICE — a narrow `Data`: a set of allowed A-XDR tags.
    Choice(&'static [u8]),
    /// The full `Data` CHOICE — any data is accepted.
    Data,
    /// Arbitrary validation (structure, nested CHOICE, …).
    Validator(&'static dyn Validator),
}

impl AttributeType {
    /// Validate `data` (decoded from the buffer) against this type.
    pub fn validate(&self, data: &Data<'_>) -> Result<()> {
        match self {
            AttributeType::Common(ct) => {
                if data.tag() == ct.tag() {
                    Ok(())
                } else {
                    Err(Error::TypeMismatch {
                        expected: ct.tag(),
                        got: data.tag(),
                    })
                }
            }
            AttributeType::Choice(tags) => {
                if tags.contains(&data.tag()) {
                    Ok(())
                } else {
                    Err(Error::ChoiceMismatch { got: data.tag() })
                }
            }
            AttributeType::Data => Ok(()),
            AttributeType::Validator(v) => v.validate(data),
        }
    }
}

/// Attribute classifier (from DLMS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classifier {
    Static,
    Dynamic,
    NotDefined,
}

/// Reference info about a single attribute.
///
/// `min`/`max`/`default` are `Data` values (for numeric attributes the bounds /
/// default value; for string attributes the length / default content).
#[derive(Debug, Clone, Copy)]
pub struct AttributeInfo {
    pub data_type: AttributeType,
    pub min: Option<Data<'static>>,
    pub max: Option<Data<'static>>,
    pub default: Option<Data<'static>>,
    pub classifier: Classifier,
}

/// A COSEM interface class instance — a static object descriptor.
///
/// A descriptor identifies one COSEM object: its OBIS code ([`obis`](Self::obis)),
/// the interface class ([`class_id`](Self::class_id) and
/// [`version`](Self::version)) and the reference info of its attributes
/// ([`attributes`](Self::attributes)). The array starts at attribute 2 because
/// `logical_name` (attribute 1) is universal. Attribute values live elsewhere
/// and are stored per-attribute by the server.
pub trait InterfaceClass: Send + Sync {
    /// The interface class identifier.
    fn class_id(&self) -> ClassId;

    /// The interface class version.
    fn version(&self) -> u8;

    /// The object's OBIS code (logical name).
    fn obis(&self) -> ObisCode;

    /// Reference info of the object's attributes, starting at attribute 2.
    fn attributes(&self) -> &'static [AttributeInfo];

    /// Key of attribute `attribute_id`, if this object exposes it.
    fn attr_key(&self, attribute_id: u8) -> Option<AttributeKey> {
        if attribute_id == 0 {
            return None;
        }
        if attribute_id == 1 {
            return Some(self.logical_name());
        }
        let idx = attribute_id as usize - 2;
        (idx < self.attributes().len()).then(|| AttributeKey::new(self.obis(), attribute_id))
    }

    /// Key of the `logical_name` attribute (attribute 1, present in every class).
    fn logical_name(&self) -> AttributeKey {
        AttributeKey::new(self.obis(), 1)
    }
}

/// One entry of the LN association `object_list` attribute (attribute 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectListItem {
    pub class_id: ClassId,
    pub version: u8,
    pub logical_name: ObisCode,
}

/// One entry of the SN association `object_list` attribute (attribute 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnObjectListItem {
    pub base_name: u16,
    pub class_id: ClassId,
    pub version: u8,
    pub logical_name: ObisCode,
}

/// The `xDLMS context info` structure (association attribute 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdlmsContextInfo {
    pub conformance: u32,
    pub max_receive_pdu_size: u16,
    pub max_send_pdu_size: u16,
}

/// `associated_partners_type ::= structure { client_SAP: integer, server_SAP: long-unsigned }`
/// (association attribute 3, shared by Association SN and LN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssociatedPartners {
    /// The client SAP (range 0…0x7F).
    pub client_sap: i8,
    /// The server SAP (range 0x0000…0x3FFF).
    pub server_sap: u16,
}

impl AssociatedPartners {
    pub const fn new(client_sap: i8, server_sap: u16) -> Self {
        AssociatedPartners { client_sap, server_sap }
    }
}

impl Default for AssociatedPartners {
    fn default() -> Self {
        AssociatedPartners::new(0, 0)
    }
}

impl<'a> FromStructure<'a> for AssociatedPartners {
    fn from_structure(fields: &'a [Data<'a>]) -> cosempdu::Result<Self> {
        if fields.len() != 2 {
            return Err(cosempdu::Error::Message("expected structure { integer, long-unsigned }"));
        }
        let client_sap = fields[0]
            .as_integer()
            .ok_or(cosempdu::Error::Message("field 0 must be integer"))?;
        let server_sap = fields[1]
            .as_long_unsigned()
            .ok_or(cosempdu::Error::Message("field 1 must be long-unsigned"))?;
        Ok(AssociatedPartners { client_sap, server_sap })
    }
}

impl Codec for AssociatedPartners {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::Structure(&[Data::Integer(self.client_sap), Data::LongUnsigned(self.server_sap)]).put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        *self = data.recast::<AssociatedPartners>()?;
        Ok(())
    }

    fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
        Some(self)
    }
}

impl StreamSink for AssociatedPartners {
    fn scalar(&mut self, tag: u8, bytes: &[u8], _index: usize) -> cosempdu::Result<()> {
        match tag {
            15 => self.client_sap = bytes[0] as i8,
            18 => self.server_sap = u16::from_be_bytes([bytes[0], bytes[1]]),
            _ => return Err(cosempdu::Error::Message("unexpected scalar in AssociatedPartners")),
        }
        Ok(())
    }

    fn composite_begin(&mut self, tag: u8, count: usize) -> cosempdu::Result<()> {
        if tag != 2 || count != 2 {
            return Err(cosempdu::Error::Message("AssociatedPartners expects a structure of two fields"));
        }
        Ok(())
    }
}

/// Validates an `associated_partners_type` value.
#[derive(Debug)]
pub struct AssociatedPartnersValidator;

impl Validator for AssociatedPartnersValidator {
    fn validate(&self, data: &Data<'_>) -> Result<()> {
        data.recast::<AssociatedPartners>().map(|_| ()).map_err(Error::from)
    }
}

/// Static `associated_partners_type` validator (as a trait object).
pub const ASSOCIATED_PARTNERS_VALIDATOR: &dyn Validator = &AssociatedPartnersValidator;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_descriptors() {
        let d = DataObject::new("0.0.96.1.0.255".parse().unwrap());
        let r = Register::new("1.0.1.8.0.255".parse().unwrap());
        let e = ExtendedRegister::new("1.0.1.8.0.255".parse().unwrap());
        let c = Clock::new("0.0.1.0.0.255".parse().unwrap());
        let sn = AssociationSn::new("0.0.40.0.0.255".parse().unwrap());
        let ln = AssociationLn::new("0.0.40.0.0.255".parse().unwrap());
        let ra = RegisterActivation::new("0.0.96.1.0.255".parse().unwrap());

        assert_eq!((d.class_id(), d.version()), (ClassId::Data, V0));
        assert_eq!((r.class_id(), r.version()), (ClassId::Register, V0));
        assert_eq!((e.class_id(), e.version()), (ClassId::ExtendedRegister, V0));
        assert_eq!((c.class_id(), c.version()), (ClassId::Clock, V0));
        assert_eq!((sn.class_id(), sn.version()), (ClassId::AssociationSn, V4));
        assert_eq!((ln.class_id(), ln.version()), (ClassId::AssociationLn, V1));
        assert_eq!((ra.class_id(), ra.version()), (ClassId::RegisterActivation, V0));

        assert_eq!(d.obis().to_string(), "0.0.96.1.0.255");
        assert_eq!(r.obis().to_string(), "1.0.1.8.0.255");

        // attribute counts (logical_name is universal, not in the array)
        assert_eq!(d.attributes().len(), 1);
        assert_eq!(r.attributes().len(), 2);
        assert_eq!(e.attributes().len(), 4);
        assert_eq!(c.attributes().len(), 7);
        assert_eq!(sn.attributes().len(), 8);
        assert_eq!(ln.attributes().len(), 7);
        assert_eq!(ra.attributes().len(), 3);

        // attr_key: logical_name + declared attributes only
        assert_eq!(r.attr_key(1).map(|k| k.attribute_id), Some(1));
        assert_eq!(r.attr_key(2).map(|k| k.attribute_id), Some(2));
        assert_eq!(r.attr_key(3).map(|k| k.attribute_id), Some(3));
        assert_eq!(r.attr_key(4), None);
        assert_eq!(r.attr_key(0), None);
    }

    #[test]
    fn attributes_metadata_is_consistent() {
        let d = DataObject::new("0.0.96.1.0.255".parse().unwrap());
        let r = Register::new("1.0.1.8.0.255".parse().unwrap());
        let e = ExtendedRegister::new("1.0.1.8.0.255".parse().unwrap());
        let c = Clock::new("0.0.1.0.0.255".parse().unwrap());
        let sn = AssociationSn::new("0.0.40.0.0.255".parse().unwrap());
        let ln = AssociationLn::new("0.0.40.0.0.255".parse().unwrap());
        let ra = RegisterActivation::new("0.0.96.1.0.255".parse().unwrap());

        let objects: &[&dyn InterfaceClass] = &[&d, &r, &e, &c, &sn, &ln, &ra];
        for obj in objects {
            for info in obj.attributes() {
                if let Some(v) = info.min {
                    assert!(info.data_type.validate(&v).is_ok(), "min invalid for {}", obj.obis());
                }
                if let Some(v) = info.max {
                    assert!(info.data_type.validate(&v).is_ok(), "max invalid for {}", obj.obis());
                }
                if let Some(v) = info.default {
                    assert!(
                        info.data_type.validate(&v).is_ok(),
                        "default invalid for {}",
                        obj.obis()
                    );
                }
            }
        }
    }

    #[test]
    fn associated_partners_type() {
        use cosempdu::buffer::{ByteBuffer, Reader};
        use cosempdu::data::{Arena, Codec, Data};
        use cosempdu::stream::StreamDecoder;

        let ap = Data::Structure(&[Data::Integer(0x10), Data::LongUnsigned(0x1234)])
            .recast::<AssociatedPartners>()
            .unwrap();
        assert_eq!(ap.client_sap, 0x10);
        assert_eq!(ap.server_sap, 0x1234);

        assert!(Data::Structure(&[Data::Integer(1)])
            .recast::<AssociatedPartners>()
            .is_err());
        assert!(Data::Structure(&[Data::Integer(1), Data::Integer(2)])
            .recast::<AssociatedPartners>()
            .is_err());

        let mut backing = [0u8; 16];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            ap.put(&mut buf).unwrap()
        };
        assert_eq!(&backing[..n], &[0x02, 0x02, 0x0F, 0x10, 0x12, 0x12, 0x34]);

        // Decode (get) roundtrip.
        let mut arena_storage = [core::mem::MaybeUninit::uninit(); 8];
        let mut arena = Arena::new(&mut arena_storage);
        let mut reader = Reader::new(&backing[..n]);
        let decoded = AssociatedPartners::get(&mut reader, &mut arena).unwrap();
        assert_eq!(decoded, ap);

        // Streaming decode (stream_sink).
        let mut streamed = AssociatedPartners::default();
        {
            let mut dec = StreamDecoder::new(&mut streamed);
            for chunk in backing[..n].chunks(2) {
                dec.push(chunk).unwrap();
            }
            dec.finish().unwrap();
        }
        assert_eq!(streamed, ap);
    }
}


