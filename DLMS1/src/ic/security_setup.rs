//! COSEM interface class "Security setup" (class_id 64, version 1).

use cosempdu::data::{Data, FromStructure};

use crate::error::{Error, Result};
use crate::ic::{
    AttributeInfo, AttributeKey, AttributeType, ClassId, Classifier, CommonDataType,
    InterfaceClass, Validator, V1,
};
use crate::obis::ObisCode;

/// Attribute 2 — `security_policy` (enum).
pub const ATTR_SECURITY_POLICY: i8 = 2;
/// Attribute 3 — `security_suite` (enum).
pub const ATTR_SECURITY_SUITE: i8 = 3;
/// Attribute 4 — `client_system_title` (octet-string).
pub const ATTR_CLIENT_SYSTEM_TITLE: i8 = 4;
/// Attribute 5 — `server_system_title` (octet-string).
pub const ATTR_SERVER_SYSTEM_TITLE: i8 = 5;
/// Attribute 6 — `certificates` (array of `certificate_info`).
pub const ATTR_CERTIFICATES: i8 = 6;

/// Bits of the `security_policy` enum (interpreted as an unsigned bitmask).
pub mod security_policy {
    /// authenticated request (bit 2).
    pub const AUTHENTICATED_REQUEST: u8 = 1 << 2;
    /// encrypted request (bit 3).
    pub const ENCRYPTED_REQUEST: u8 = 1 << 3;
    /// digitally signed request (bit 4).
    pub const DIGITALLY_SIGNED_REQUEST: u8 = 1 << 4;
    /// authenticated response (bit 5).
    pub const AUTHENTICATED_RESPONSE: u8 = 1 << 5;
    /// encrypted response (bit 6).
    pub const ENCRYPTED_RESPONSE: u8 = 1 << 6;
    /// digitally signed response (bit 7).
    pub const DIGITALLY_SIGNED_RESPONSE: u8 = 1 << 7;
}

/// `security_suite` enum: the security algorithms available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecuritySuite {
    /// (0) AES-GCM-128 authenticated encryption and AES-128 key wrap.
    AesGcm128 = 0,
    /// (1) AES-GCM-128, ECDSA P-256, ECDH P-256, SHA-256, V.44, AES-128 key wrap.
    AesGcm128EcdsaP256 = 1,
    /// (2) AES-GCM-256, ECDSA P-384, ECDH P-384, SHA-384, V.44, AES-256 key wrap.
    AesGcm256EcdsaP384 = 2,
}

impl SecuritySuite {
    /// The numeric suite identifier.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Dedicated-key size for this suite (AES-128 → 16 bytes, AES-256 → 32).
    pub const fn key_len(self) -> usize {
        match self {
            SecuritySuite::AesGcm128 | SecuritySuite::AesGcm128EcdsaP256 => 16,
            SecuritySuite::AesGcm256EcdsaP384 => 32,
        }
    }

    /// Parse a numeric suite identifier (3..15 are reserved).
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => SecuritySuite::AesGcm128,
            1 => SecuritySuite::AesGcm128EcdsaP256,
            2 => SecuritySuite::AesGcm256EcdsaP384,
            _ => return None,
        })
    }
}

/// `certificate_entity` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CertificateEntity {
    /// (0) server.
    Server = 0,
    /// (1) client or third party.
    ClientOrThirdParty = 1,
    /// (2) certification authority.
    CertificationAuthority = 2,
    /// (3) other.
    Other = 3,
}

impl CertificateEntity {
    /// Parse a numeric entity identifier.
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => CertificateEntity::Server,
            1 => CertificateEntity::ClientOrThirdParty,
            2 => CertificateEntity::CertificationAuthority,
            3 => CertificateEntity::Other,
            _ => return None,
        })
    }
}

/// `certificate_type` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CertificateType {
    /// (0) digital signature.
    DigitalSignature = 0,
    /// (1) key agreement.
    KeyAgreement = 1,
    /// (2) TLS.
    Tls = 2,
    /// (3) other.
    Other = 3,
}

impl CertificateType {
    /// Parse a numeric type identifier.
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => CertificateType::DigitalSignature,
            1 => CertificateType::KeyAgreement,
            2 => CertificateType::Tls,
            3 => CertificateType::Other,
            _ => return None,
        })
    }
}

/// `certificate_info ::= structure` — one entry of the `certificates` attribute.
///
/// The octet-strings (`serial_number`, `issuer`, `subject`, `subject_alt_name`)
/// borrow from the decoded buffer and carry the TLV of the corresponding
/// Certificate field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateInfo<'a> {
    pub certificate_entity: CertificateEntity,
    pub certificate_type: CertificateType,
    pub serial_number: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub subject_alt_name: &'a [u8],
}

impl<'a> FromStructure<'a> for CertificateInfo<'a> {
    fn from_structure(fields: &'a [Data<'a>]) -> cosempdu::Result<Self> {
        if fields.len() != 6 {
            return Err(cosempdu::Error::Message(
                "certificate_info must be a structure of six fields",
            ));
        }
        let certificate_entity = fields[0]
            .as_enum()
            .and_then(CertificateEntity::from_u8)
            .ok_or(cosempdu::Error::Message(
                "field 0 must be a known certificate_entity",
            ))?;
        let certificate_type = fields[1]
            .as_enum()
            .and_then(CertificateType::from_u8)
            .ok_or(cosempdu::Error::Message(
                "field 1 must be a known certificate_type",
            ))?;
        let serial_number = fields[2]
            .as_octet_string()
            .ok_or(cosempdu::Error::Message("field 2 must be an octet-string"))?;
        let issuer = fields[3]
            .as_octet_string()
            .ok_or(cosempdu::Error::Message("field 3 must be an octet-string"))?;
        let subject = fields[4]
            .as_octet_string()
            .ok_or(cosempdu::Error::Message("field 4 must be an octet-string"))?;
        let subject_alt_name = fields[5]
            .as_octet_string()
            .ok_or(cosempdu::Error::Message("field 5 must be an octet-string"))?;
        Ok(CertificateInfo {
            certificate_entity,
            certificate_type,
            serial_number,
            issuer,
            subject,
            subject_alt_name,
        })
    }
}

/// Validates `certificates` (array of `certificate_info`).
#[derive(Debug)]
pub struct CertificatesValidator;

impl Validator for CertificatesValidator {
    fn validate(&self, data: &Data<'_>) -> Result<()> {
        let items = data
            .as_array()
            .ok_or(Error::Codec(cosempdu::Error::Message(
                "certificates must be an array",
            )))?;
        for item in items {
            item.recast::<CertificateInfo<'_>>().map_err(Error::from)?;
        }
        Ok(())
    }
}

/// Static `certificates` validator (as a trait object).
pub const CERTIFICATES_VALIDATOR: &dyn Validator = &CertificatesValidator;

/// COSEM interface class "Security setup" (class_id 64): a static object descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecuritySetup {
    pub obis: ObisCode,
}

impl SecuritySetup {
    pub const fn new(obis: ObisCode) -> Self {
        SecuritySetup { obis }
    }

    /// Key of the `security_policy` attribute.
    pub const fn security_policy(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_SECURITY_POLICY)
    }

    /// Key of the `security_suite` attribute.
    pub const fn security_suite(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_SECURITY_SUITE)
    }

    /// Key of the `client_system_title` attribute.
    pub const fn client_system_title(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_CLIENT_SYSTEM_TITLE)
    }

    /// Key of the `server_system_title` attribute.
    pub const fn server_system_title(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_SERVER_SYSTEM_TITLE)
    }

    /// Key of the `certificates` attribute.
    pub const fn certificates(&self) -> AttributeKey {
        AttributeKey::new(self.obis, ATTR_CERTIFICATES)
    }
}

impl InterfaceClass for SecuritySetup {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn class_id(&self) -> ClassId {
        ClassId::SecuritySetup
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
                data_type: AttributeType::Common(CommonDataType::Enum),
                min: None,
                max: None,
                default: Some(Data::Enum(0)),
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
                data_type: AttributeType::Validator(CERTIFICATES_VALIDATOR),
                min: None,
                max: None,
                default: None,
                classifier: Classifier::Dynamic,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_info() -> Data<'static> {
        Data::Structure(&[
            Data::Enum(0), // server
            Data::Enum(0), // digital signature
            Data::OctetString(&[0x02, 0x01]),
            Data::OctetString(b"CA"),
            Data::OctetString(b"server"),
            Data::OctetString(b"server.example"),
        ])
    }

    #[test]
    fn certificate_info_from_structure() {
        let ci = cert_info().recast::<CertificateInfo<'_>>().unwrap();
        assert_eq!(ci.certificate_entity, CertificateEntity::Server);
        assert_eq!(ci.certificate_type, CertificateType::DigitalSignature);
        assert_eq!(ci.serial_number, &[0x02, 0x01]);
        assert_eq!(ci.issuer, b"CA");
        assert_eq!(ci.subject, b"server");
        assert_eq!(ci.subject_alt_name, b"server.example");
    }

    #[test]
    fn certificate_info_rejects_bad_shape() {
        // Too few fields.
        let bad = Data::Structure(&[Data::Enum(0), Data::Enum(0)]);
        assert!(bad.recast::<CertificateInfo<'_>>().is_err());

        // Unknown certificate_entity.
        let bad = Data::Structure(&[
            Data::Enum(99),
            Data::Enum(0),
            Data::OctetString(b"a"),
            Data::OctetString(b"b"),
            Data::OctetString(b"c"),
            Data::OctetString(b"d"),
        ]);
        assert!(bad.recast::<CertificateInfo<'_>>().is_err());
    }

    #[test]
    fn certificates_validator_accept_and_reject() {
        let ci = cert_info();
        assert!(CERTIFICATES_VALIDATOR.validate(&Data::Array(&[ci])).is_ok());

        // Top-level must be an array, not a structure.
        assert!(CERTIFICATES_VALIDATOR.validate(&ci).is_err());
    }

    #[test]
    fn class_descriptor() {
        let ss = SecuritySetup::new(ObisCode::new(0, 0, 43, 0, 0, 255));
        assert_eq!((ss.class_id(), ss.version()), (ClassId::SecuritySetup, V1));
        assert_eq!(ss.attributes().len(), 5);
        assert_eq!(ss.attr_key(2).map(|k| k.attribute_id), Some(2));
        assert_eq!(ss.attr_key(6).map(|k| k.attribute_id), Some(6));
        assert_eq!(ss.attr_key(7), None);
    }
}
