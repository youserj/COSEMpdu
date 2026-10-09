//! ACSE (Association Control Service Element) APDUs, BER encoded.
//!
//! Mirrors `src/COSEMpdu/acse.py`: AARQ/AARE/RLRQ/RLRE APDUs used during
//! DLMS/COSEM association establishment and release. Encoding follows X.690
//! with explicit/implicit context tagging.

use crate::ber::{decode_signed, put_signed, put_tlv, with_content};
use bytebuffer::{ByteBuffer, Reader};
use crate::error::{Error, Result};
use crate::x680::{Class, Tag, UniversalTag};
use crate::x690::{get_tag, Length};

fn ctx(number: u64, constructed: bool) -> Tag {
    Tag {
        class: Class::Context,
        number,
        constructed,
    }
}

fn app(number: u64) -> Tag {
    Tag {
        class: Class::Application,
        number,
        constructed: true,
    }
}

/// Read one TLV (tag + content) from a buffer.
fn read_tlv<'a>(buf: &mut Reader<'a>) -> Result<(Tag, &'a [u8])> {
    let tag = get_tag(buf)?;
    let length = Length::get(buf)?;
    if length.value < 0 {
        return Err(Error::Unsupported {
            what: "indefinite length in ACSE",
        });
    }
    let content = buf.read(length.value as usize)?;
    Ok((tag, content))
}

/// Decode the inner TLV content of an EXPLICIT field.
fn unwrap_explicit<'a>(content: &'a [u8]) -> Result<(Tag, &'a [u8])> {
    read_tlv(&mut Reader::new(content))
}

fn put_explicit_oid(
    buf: &mut ByteBuffer<'_>,
    number: u64,
    value: &ApplicationContextName,
) -> Result<usize> {
    with_content(buf, &ctx(number, true), |b| {
        with_content(b, &Tag::universal(UniversalTag::ObjectIdentifier), |ib| {
            value.put_content(ib)
        })
    })
}

fn put_explicit_octet_string(
    buf: &mut ByteBuffer<'_>,
    number: u64,
    bytes: &[u8],
) -> Result<usize> {
    with_content(buf, &ctx(number, true), |b| {
        put_tlv(b, &Tag::universal(UniversalTag::OctetString), bytes)
    })
}

fn put_explicit_integer(buf: &mut ByteBuffer<'_>, number: u64, value: i64) -> Result<usize> {
    with_content(buf, &ctx(number, true), |b| {
        with_content(b, &Tag::universal(UniversalTag::Integer), |ib| {
            put_signed(ib, value)
        })
    })
}

fn put_implicit_integer(buf: &mut ByteBuffer<'_>, number: u64, value: i64) -> Result<usize> {
    with_content(buf, &ctx(number, false), |b| put_signed(b, value))
}

fn put_implicit_bit_string(
    buf: &mut ByteBuffer<'_>,
    number: u64,
    content: &[u8],
) -> Result<usize> {
    put_tlv(buf, &ctx(number, false), content)
}

/// Encode an EXPLICIT `Authentication-value` whose chosen alternative is
/// `charstring [0] IMPLICIT GraphicString`: `<ctx(n,true)><len> 80 <len> <bytes>`.
fn put_explicit_charstring(
    buf: &mut ByteBuffer<'_>,
    number: u64,
    bytes: &[u8],
) -> Result<usize> {
    with_content(buf, &ctx(number, true), |b| {
        put_tlv(b, &ctx(0, false), bytes)
    })
}

// ---------------------------------------------------------------------------
// DLMS/COSEM ACSE OBJECT IDENTIFIERs
// ---------------------------------------------------------------------------
//
// In DLMS/COSEM the only OBJECT IDENTIFIERs are the ACSE
// `application-context-name` and `mechanism-name`. Both share the fixed prefix
// `{ 2 16 756 5 8 }` and are fully determined by their two trailing arcs:
//
//   application-context-name ::= { 2 16 756 5 8 1 X }
//   mechanism-name          ::= { 2 16 756 5 8 2 X }
//
// Rather than modeling these with the generic abstract `Value`, they are
// represented here as closed, `Copy` enums (heap-free), with an `Unknown`
// variant to preserve forward compatibility with future context/mechanism
// identifiers.

/// The fixed DLMS/COSEM OBJECT IDENTIFIER prefix `{ 2 16 756 5 8 }`.
const ACSE_OID_PREFIX: [u64; 5] = [2, 16, 756, 5, 8];

/// Base-128 content of the fixed prefix `{ 2 16 756 5 8 }`:
///   first subidentifier 2*40+16 = 96  -> 0x60
///   756 -> 0x85 0x74
///   5   -> 0x05
///   8   -> 0x08
const ACSE_OID_PREFIX_CONTENT: [u8; 5] = [0x60, 0x85, 0x74, 0x05, 0x08];

/// Discriminator arc for `application-context-name` (`{ 2 16 756 5 8 1 X }`).
const CONTEXT_DISCRIMINATOR: u8 = 1;

/// Discriminator arc for `mechanism-name` (`{ 2 16 756 5 8 2 X }`).
const MECHANISM_DISCRIMINATOR: u8 = 2;

/// Encode a `mechanism-name` as an IMPLICIT-tagged OBJECT IDENTIFIER: the
/// context tag replaces the universal tag and the content is the raw base-128
/// subidentifiers (no inner tag 0x06).
fn put_implicit_oid(buf: &mut ByteBuffer<'_>, number: u64, value: &MechanismName) -> Result<usize> {
    with_content(buf, &ctx(number, false), |b| value.put_content(b))
}

/// DLMS/COSEM `application-context-name` (`{ 2 16 756 5 8 1 X }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationContextName {
    /// Logical-name referencing, no ciphering (`{ 2 16 756 5 8 1 1 }`).
    LogicalNameNoCiphering,
    /// Short-name referencing, no ciphering (`{ 2 16 756 5 8 1 2 }`).
    ShortNameNoCiphering,
    /// Logical-name referencing, with ciphering (`{ 2 16 756 5 8 1 3 }`).
    LogicalNameCiphering,
    /// Short-name referencing, with ciphering (`{ 2 16 756 5 8 1 4 }`).
    ShortNameCiphering,
    /// An unrecognized application-context (trailing arc), preserved for
    /// forward compatibility. The trailing arc is at most 127 (a single
    /// base-128 octet); larger values are rejected when decoding.
    Unknown(u8),
}

impl ApplicationContextName {
    /// The trailing arc value (`X` in `{ 2 16 756 5 8 1 X }`).
    pub fn value(self) -> u8 {
        match self {
            ApplicationContextName::LogicalNameNoCiphering => 1,
            ApplicationContextName::ShortNameNoCiphering => 2,
            ApplicationContextName::LogicalNameCiphering => 3,
            ApplicationContextName::ShortNameCiphering => 4,
            ApplicationContextName::Unknown(v) => v,
        }
    }

    /// The full seven arcs `{ 2 16 756 5 8 1 X }`.
    pub fn to_arcs(self) -> [u64; 7] {
        let mut arcs = [0u64; 7];
        arcs[..5].copy_from_slice(&ACSE_OID_PREFIX);
        arcs[5] = 1;
        arcs[6] = self.value() as u64;
        arcs
    }

    /// Map a trailing arc (`X`, already known to be `<= 127`) to the variant.
    fn from_trailing(x: u8) -> Self {
        match x {
            1 => ApplicationContextName::LogicalNameNoCiphering,
            2 => ApplicationContextName::ShortNameNoCiphering,
            3 => ApplicationContextName::LogicalNameCiphering,
            4 => ApplicationContextName::ShortNameCiphering,
            v => ApplicationContextName::Unknown(v),
        }
    }

    /// Parse from a decoded OBJECT IDENTIFIER arc list.
    pub fn from_arcs(arcs: &[u64]) -> Result<Self> {
        if arcs.len() != 7 || arcs[..5] != ACSE_OID_PREFIX[..] || arcs[5] != 1 {
            return Err(Error::InvalidAcseOid);
        }
        if arcs[6] > 127 {
            return Err(Error::InvalidAcseOid);
        }
        Ok(Self::from_trailing(arcs[6] as u8))
    }

    /// Write the raw base-128 OBJECT IDENTIFIER content (no tag) into `buf`.
    ///
    /// The content is always exactly seven octets: the fixed prefix
    /// `{ 2 16 756 5 8 }`, the context discriminator `1`, and the trailing arc
    /// `X` (a single octet since `X <= 127`).
    pub fn put_content(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        buf.write(&ACSE_OID_PREFIX_CONTENT)?;
        buf.put_u8(CONTEXT_DISCRIMINATOR)?;
        buf.put_u8(self.value())?;
        Ok(7)
    }

    /// Decode the raw base-128 OBJECT IDENTIFIER content (no tag) directly,
    /// without materializing an intermediate arc array.
    pub fn from_content(content: &[u8]) -> Result<Self> {
        if content.len() != 7
            || content[..5] != ACSE_OID_PREFIX_CONTENT[..]
            || content[5] != CONTEXT_DISCRIMINATOR
            || content[6] > 127
        {
            return Err(Error::InvalidAcseOid);
        }
        Ok(Self::from_trailing(content[6]))
    }
}

/// DLMS/COSEM `mechanism-name` (`{ 2 16 756 5 8 2 X }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MechanismName {
    /// Lowest level security, no authentication (`{ 2 16 756 5 8 2 0 }`).
    LowestLevelSecurity,
    /// Low-level security, LLS (`{ 2 16 756 5 8 2 1 }`).
    LowLevelSecurity,
    /// High-level security (`{ 2 16 756 5 8 2 2 }`).
    HighLevelSecurity,
    /// High-level security, MD5 (`{ 2 16 756 5 8 2 3 }`).
    HighLevelSecurityMd5,
    /// High-level security, SHA-1 (`{ 2 16 756 5 8 2 4 }`).
    HighLevelSecuritySha1,
    /// High-level security, GMAC (`{ 2 16 756 5 8 2 5 }`).
    HighLevelSecurityGmac,
    /// High-level security, SHA-256 (`{ 2 16 756 5 8 2 6 }`).
    HighLevelSecuritySha256,
    /// High-level security, ECDSA (`{ 2 16 756 5 8 2 7 }`).
    HighLevelSecurityEcdsa,
    /// An unrecognized mechanism (trailing arc), preserved for forward
    /// compatibility. The trailing arc is at most 127 (a single base-128
    /// octet); larger values are rejected when decoding.
    Unknown(u8),
}

impl MechanismName {
    /// The trailing arc value (`X` in `{ 2 16 756 5 8 2 X }`).
    pub fn value(self) -> u8 {
        match self {
            MechanismName::LowestLevelSecurity => 0,
            MechanismName::LowLevelSecurity => 1,
            MechanismName::HighLevelSecurity => 2,
            MechanismName::HighLevelSecurityMd5 => 3,
            MechanismName::HighLevelSecuritySha1 => 4,
            MechanismName::HighLevelSecurityGmac => 5,
            MechanismName::HighLevelSecuritySha256 => 6,
            MechanismName::HighLevelSecurityEcdsa => 7,
            MechanismName::Unknown(v) => v,
        }
    }

    /// The full seven arcs `{ 2 16 756 5 8 2 X }`.
    pub fn to_arcs(self) -> [u64; 7] {
        let mut arcs = [0u64; 7];
        arcs[..5].copy_from_slice(&ACSE_OID_PREFIX);
        arcs[5] = 2;
        arcs[6] = self.value() as u64;
        arcs
    }

    /// Map a trailing arc (`X`, already known to be `<= 127`) to the variant.
    fn from_trailing(x: u8) -> Self {
        match x {
            0 => MechanismName::LowestLevelSecurity,
            1 => MechanismName::LowLevelSecurity,
            2 => MechanismName::HighLevelSecurity,
            3 => MechanismName::HighLevelSecurityMd5,
            4 => MechanismName::HighLevelSecuritySha1,
            5 => MechanismName::HighLevelSecurityGmac,
            6 => MechanismName::HighLevelSecuritySha256,
            7 => MechanismName::HighLevelSecurityEcdsa,
            v => MechanismName::Unknown(v),
        }
    }

    /// Parse from a decoded OBJECT IDENTIFIER arc list.
    pub fn from_arcs(arcs: &[u64]) -> Result<Self> {
        if arcs.len() != 7 || arcs[..5] != ACSE_OID_PREFIX[..] || arcs[5] != 2 {
            return Err(Error::InvalidAcseOid);
        }
        if arcs[6] > 127 {
            return Err(Error::InvalidAcseOid);
        }
        Ok(Self::from_trailing(arcs[6] as u8))
    }

    /// Write the raw base-128 OBJECT IDENTIFIER content (no tag) into `buf`.
    ///
    /// The content is always exactly seven octets: the fixed prefix
    /// `{ 2 16 756 5 8 }`, the mechanism discriminator `2`, and the trailing
    /// arc `X` (a single octet since `X <= 127`).
    pub fn put_content(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        buf.write(&ACSE_OID_PREFIX_CONTENT)?;
        buf.put_u8(MECHANISM_DISCRIMINATOR)?;
        buf.put_u8(self.value())?;
        Ok(7)
    }

    /// Decode the raw base-128 OBJECT IDENTIFIER content (no tag) directly,
    /// without materializing an intermediate arc array.
    pub fn from_content(content: &[u8]) -> Result<Self> {
        if content.len() != 7
            || content[..5] != ACSE_OID_PREFIX_CONTENT[..]
            || content[5] != MECHANISM_DISCRIMINATOR
            || content[6] > 127
        {
            return Err(Error::InvalidAcseOid);
        }
        Ok(Self::from_trailing(content[6]))
    }
}

/// AARQ-apdu ::= [APPLICATION 0] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AARQapdu<'a> {
    /// `protocol-version [0] IMPLICIT BIT STRING` (DEFAULT `{version1}`).
    pub protocol_version: Option<&'a [u8]>,
    /// `application-context-name [1]` (OBJECT IDENTIFIER).
    pub application_context_name: ApplicationContextName,
    /// `called-AP-title [2]` (OCTET STRING).
    pub called_ap_title: Option<&'a [u8]>,
    /// `called-AE-qualifier [3]` (OCTET STRING).
    pub called_ae_qualifier: Option<&'a [u8]>,
    /// `called-AP-invocation-id [4]` (INTEGER).
    pub called_ap_invocation_id: Option<i64>,
    /// `called-AE-invocation-id [5]` (INTEGER).
    pub called_ae_invocation_id: Option<i64>,
    /// `calling-AP-title [6]` (OCTET STRING).
    pub calling_ap_title: Option<&'a [u8]>,
    /// `calling-AE-qualifier [7]` (OCTET STRING).
    pub calling_ae_qualifier: Option<&'a [u8]>,
    /// `calling-AP-invocation-id [8]` (INTEGER).
    pub calling_ap_invocation_id: Option<i64>,
    /// `calling-AE-invocation-id [9]` (INTEGER).
    pub calling_ae_invocation_id: Option<i64>,
    /// `sender-acse-requirements [10] IMPLICIT BIT STRING`.
    pub sender_acse_requirements: Option<&'a [u8]>,
    /// `mechanism-name [11] IMPLICIT` (OBJECT IDENTIFIER).
    pub mechanism_name: Option<MechanismName>,
    /// `calling-authentication-value [12] EXPLICIT` (charstring).
    pub calling_authentication_value: Option<&'a [u8]>,
    /// `implementation-information [29] IMPLICIT`.
    pub implementation_information: Option<&'a [u8]>,
    /// `user-information [30] EXPLICIT` (OCTET STRING).
    pub user_information: Option<&'a [u8]>,
}

impl<'a> AARQapdu<'a> {
    pub fn new(application_context_name: ApplicationContextName) -> Self {
        AARQapdu {
            protocol_version: None,
            application_context_name,
            called_ap_title: None,
            called_ae_qualifier: None,
            called_ap_invocation_id: None,
            called_ae_invocation_id: None,
            calling_ap_title: None,
            calling_ae_qualifier: None,
            calling_ap_invocation_id: None,
            calling_ae_invocation_id: None,
            sender_acse_requirements: None,
            mechanism_name: None,
            calling_authentication_value: None,
            implementation_information: None,
            user_information: None,
        }
    }

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        with_content(buf, &app(0), |b| {
            let mut written = 0usize;
            if let Some(pv) = &self.protocol_version {
                written += put_implicit_bit_string(b, 0, pv)?;
            }
            written += put_explicit_oid(b, 1, &self.application_context_name)?;
            if let Some(v) = &self.called_ap_title {
                written += put_explicit_octet_string(b, 2, v)?;
            }
            if let Some(v) = &self.called_ae_qualifier {
                written += put_explicit_octet_string(b, 3, v)?;
            }
            if let Some(v) = self.called_ap_invocation_id {
                written += put_implicit_integer(b, 4, v)?;
            }
            if let Some(v) = self.called_ae_invocation_id {
                written += put_implicit_integer(b, 5, v)?;
            }
            if let Some(v) = &self.calling_ap_title {
                written += put_explicit_octet_string(b, 6, v)?;
            }
            if let Some(v) = &self.calling_ae_qualifier {
                written += put_explicit_octet_string(b, 7, v)?;
            }
            if let Some(v) = self.calling_ap_invocation_id {
                written += put_implicit_integer(b, 8, v)?;
            }
            if let Some(v) = self.calling_ae_invocation_id {
                written += put_implicit_integer(b, 9, v)?;
            }
            if let Some(v) = &self.sender_acse_requirements {
                written += put_implicit_bit_string(b, 10, v)?;
            }
            if let Some(mn) = self.mechanism_name {
                written += put_implicit_oid(b, 11, &mn)?;
            }
            if let Some(v) = &self.calling_authentication_value {
                written += put_explicit_charstring(b, 12, v)?;
            }
            if let Some(v) = &self.implementation_information {
                written += put_tlv(b, &ctx(29, false), v)?;
            }
            if let Some(v) = &self.user_information {
                written += put_explicit_octet_string(b, 30, v)?;
            }
            Ok(written)
        })
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let (tag, content) = read_tlv(buf)?;
        if tag != app(0) {
            return Err(Error::Message("expected AARQ-apdu [APPLICATION 0]"));
        }
        let mut inner = Reader::new(content);
        let mut apdu = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        let mut application_context_name = None;
        while inner.pos() < inner.len() {
            let (ftag, fcontent) = read_tlv(&mut inner)?;
            match ftag.number {
                0 => apdu.protocol_version = Some(fcontent),
                1 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    application_context_name =
                        Some(ApplicationContextName::from_content(ocontent)?);
                }
                2 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    apdu.called_ap_title = Some(ocontent);
                }
                3 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    apdu.called_ae_qualifier = Some(ocontent);
                }
                4 => apdu.called_ap_invocation_id = Some(decode_signed(fcontent)?),
                5 => apdu.called_ae_invocation_id = Some(decode_signed(fcontent)?),
                6 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    apdu.calling_ap_title = Some(ocontent);
                }
                7 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    apdu.calling_ae_qualifier = Some(ocontent);
                }
                8 => apdu.calling_ap_invocation_id = Some(decode_signed(fcontent)?),
                9 => apdu.calling_ae_invocation_id = Some(decode_signed(fcontent)?),
                10 => apdu.sender_acse_requirements = Some(fcontent),
                11 => apdu.mechanism_name = Some(MechanismName::from_content(fcontent)?),
                12 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    apdu.calling_authentication_value = Some(ocontent);
                }
                29 => apdu.implementation_information = Some(fcontent),
                30 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    apdu.user_information = Some(ocontent);
                }
                _ => {}
            }
        }
        apdu.application_context_name = application_context_name
            .ok_or_else(|| Error::message("missing application-context-name"))?;
        Ok(apdu)
    }
}

/// AARE-apdu ::= [APPLICATION 1] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AAREapdu<'a> {
    pub protocol_version: Option<&'a [u8]>,
    pub application_context_name: ApplicationContextName,
    /// `result [2] Association-result` (INTEGER).
    pub result: i64,
    /// `result-source-diagnostic [3] Associate-source-diagnostic` (INTEGER).
    pub result_source_diagnostic: i64,
    /// `responding-AP-title [4]` (OCTET STRING).
    pub responding_ap_title: Option<&'a [u8]>,
    /// `responding-AE-qualifier [5]` (OCTET STRING).
    pub responding_ae_qualifier: Option<&'a [u8]>,
    /// `responding-AP-invocation-id [6]` (INTEGER).
    pub responding_ap_invocation_id: Option<i64>,
    /// `responding-AE-invocation-id [7]` (INTEGER).
    pub responding_ae_invocation_id: Option<i64>,
    /// `responder-acse-requirements [8] IMPLICIT BIT STRING`.
    pub responder_acse_requirements: Option<&'a [u8]>,
    /// `mechanism-name [9] IMPLICIT` (OBJECT IDENTIFIER).
    pub mechanism_name: Option<MechanismName>,
    /// `responding-authentication-value [10] EXPLICIT` (charstring).
    pub responding_authentication_value: Option<&'a [u8]>,
    /// `implementation-information [29] IMPLICIT`.
    pub implementation_information: Option<&'a [u8]>,
    pub user_information: Option<&'a [u8]>,
}

impl<'a> AAREapdu<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        with_content(buf, &app(1), |b| {
            let mut written = 0usize;
            if let Some(pv) = &self.protocol_version {
                written += put_implicit_bit_string(b, 0, pv)?;
            }
            written += put_explicit_oid(b, 1, &self.application_context_name)?;
            written += put_explicit_integer(b, 2, self.result)?;
            // result-source-diagnostic [3] EXPLICIT Associate-source-diagnostic,
            // acse-service-user [1] EXPLICIT INTEGER.
            written += with_content(b, &ctx(3, true), |ob| {
                with_content(ob, &ctx(1, true), |ib| {
                    with_content(ib, &Tag::universal(UniversalTag::Integer), |jb| {
                        put_signed(jb, self.result_source_diagnostic)
                    })
                })
            })?;
            if let Some(v) = &self.responding_ap_title {
                written += put_explicit_octet_string(b, 4, v)?;
            }
            if let Some(v) = &self.responding_ae_qualifier {
                written += put_explicit_octet_string(b, 5, v)?;
            }
            if let Some(v) = self.responding_ap_invocation_id {
                written += put_implicit_integer(b, 6, v)?;
            }
            if let Some(v) = self.responding_ae_invocation_id {
                written += put_implicit_integer(b, 7, v)?;
            }
            if let Some(v) = &self.responder_acse_requirements {
                written += put_implicit_bit_string(b, 8, v)?;
            }
            if let Some(mn) = self.mechanism_name {
                written += put_implicit_oid(b, 9, &mn)?;
            }
            if let Some(v) = &self.responding_authentication_value {
                written += put_explicit_charstring(b, 10, v)?;
            }
            if let Some(v) = &self.implementation_information {
                written += put_tlv(b, &ctx(29, false), v)?;
            }
            if let Some(v) = &self.user_information {
                written += put_explicit_octet_string(b, 30, v)?;
            }
            Ok(written)
        })
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let (tag, content) = read_tlv(buf)?;
        if tag != app(1) {
            return Err(Error::Message("expected AARE-apdu [APPLICATION 1]"));
        }
        let mut inner = Reader::new(content);
        let mut protocol_version = None;
        let mut application_context_name = None;
        let mut result = 0;
        let mut result_source_diagnostic = 0;
        let mut responding_ap_title = None;
        let mut responding_ae_qualifier = None;
        let mut responding_ap_invocation_id = None;
        let mut responding_ae_invocation_id = None;
        let mut responder_acse_requirements = None;
        let mut mechanism_name = None;
        let mut responding_authentication_value = None;
        let mut implementation_information = None;
        let mut user_information = None;
        while inner.pos() < inner.len() {
            let (ftag, fcontent) = read_tlv(&mut inner)?;
            match ftag.number {
                0 => protocol_version = Some(fcontent),
                1 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    application_context_name =
                        Some(ApplicationContextName::from_content(ocontent)?);
                }
                2 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    result = decode_signed(ocontent)?;
                }
                3 => {
                    let (_a3, inner1) = unwrap_explicit(fcontent)?;
                    let (_a1, ocontent) = unwrap_explicit(inner1)?;
                    result_source_diagnostic = decode_signed(ocontent)?;
                }
                4 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    responding_ap_title = Some(ocontent);
                }
                5 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    responding_ae_qualifier = Some(ocontent);
                }
                6 => responding_ap_invocation_id = Some(decode_signed(fcontent)?),
                7 => responding_ae_invocation_id = Some(decode_signed(fcontent)?),
                8 => responder_acse_requirements = Some(fcontent),
                9 => mechanism_name = Some(MechanismName::from_content(fcontent)?),
                10 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    responding_authentication_value = Some(ocontent);
                }
                29 => implementation_information = Some(fcontent),
                30 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    user_information = Some(ocontent);
                }
                _ => {}
            }
        }
        Ok(AAREapdu {
            protocol_version,
            application_context_name: application_context_name
                .ok_or_else(|| Error::message("missing application-context-name"))?,
            result,
            result_source_diagnostic,
            responding_ap_title,
            responding_ae_qualifier,
            responding_ap_invocation_id,
            responding_ae_invocation_id,
            responder_acse_requirements,
            mechanism_name,
            responding_authentication_value,
            implementation_information,
            user_information,
        })
    }
}

/// RLRQ-apdu ::= [APPLICATION 2] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLRQapdu<'a> {
    pub reason: Option<i64>,
    pub user_information: Option<&'a [u8]>,
}

impl<'a> RLRQapdu<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        with_content(buf, &app(2), |b| {
            let mut written = 0usize;
            if let Some(reason) = self.reason {
                written += put_implicit_integer(b, 0, reason)?;
            }
            if let Some(ui) = &self.user_information {
                written += put_explicit_octet_string(b, 30, ui)?;
            }
            Ok(written)
        })
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let (tag, content) = read_tlv(buf)?;
        if tag != app(2) {
            return Err(Error::Message("expected RLRQ-apdu [APPLICATION 2]"));
        }
        let mut inner = Reader::new(content);
        let mut reason = None;
        let mut user_information = None;
        while inner.pos() < inner.len() {
            let (ftag, fcontent) = read_tlv(&mut inner)?;
            match ftag.number {
                0 => reason = Some(decode_signed(fcontent)?),
                30 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    user_information = Some(ocontent);
                }
                _ => {}
            }
        }
        Ok(RLRQapdu {
            reason,
            user_information,
        })
    }
}

/// RLRE-apdu ::= [APPLICATION 3] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLREapdu<'a> {
    pub reason: Option<i64>,
    pub user_information: Option<&'a [u8]>,
}

impl<'a> RLREapdu<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        with_content(buf, &app(3), |b| {
            let mut written = 0usize;
            if let Some(reason) = self.reason {
                written += put_implicit_integer(b, 0, reason)?;
            }
            if let Some(ui) = &self.user_information {
                written += put_explicit_octet_string(b, 30, ui)?;
            }
            Ok(written)
        })
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let (tag, content) = read_tlv(buf)?;
        if tag != app(3) {
            return Err(Error::Message("expected RLRE-apdu [APPLICATION 3]"));
        }
        let mut inner = Reader::new(content);
        let mut reason = None;
        let mut user_information = None;
        while inner.pos() < inner.len() {
            let (ftag, fcontent) = read_tlv(&mut inner)?;
            match ftag.number {
                0 => reason = Some(decode_signed(fcontent)?),
                30 => {
                    let (_itag, ocontent) = unwrap_explicit(fcontent)?;
                    user_information = Some(ocontent);
                }
                _ => {}
            }
        }
        Ok(RLREapdu {
            reason,
            user_information,
        })
    }
}

/// ACSE-APDU ::= CHOICE { aarq, aare, rlrq, rlre }.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ACSEApdu<'a> {
    Aarq(AARQapdu<'a>),
    Aare(AAREapdu<'a>),
    Rlrq(RLRQapdu<'a>),
    Rlre(RLREapdu<'a>),
}

impl<'a> ACSEApdu<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            ACSEApdu::Aarq(a) => a.put(buf),
            ACSEApdu::Aare(a) => a.put(buf),
            ACSEApdu::Rlrq(a) => a.put(buf),
            ACSEApdu::Rlre(a) => a.put(buf),
        }
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let start = buf.pos();
        let tag = get_tag(buf)?;
        buf.set_pos(start)?;
        match (tag.class, tag.number) {
            (Class::Application, 0) => Ok(ACSEApdu::Aarq(AARQapdu::get(buf)?)),
            (Class::Application, 1) => Ok(ACSEApdu::Aare(AAREapdu::get(buf)?)),
            (Class::Application, 2) => Ok(ACSEApdu::Rlrq(RLRQapdu::get(buf)?)),
            (Class::Application, 3) => Ok(ACSEApdu::Rlre(RLREapdu::get(buf)?)),
            _ => Err(Error::Message("unknown ACSE APDU tag")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! roundtrip {
        ($value:expr, $get:path) => {{
            let value = $value;
            let mut backing = [0u8; 4096];
            let n = {
                let mut buf = ByteBuffer::new(&mut backing);
                value.put(&mut buf).unwrap();
                buf.pos()
            };
            let expected = backing[..n].to_vec();
            let mut r = Reader::new(&backing[..n]);
            let decoded = $get(&mut r).unwrap();
            let mut backing2 = [0u8; 4096];
            let m = {
                let mut buf = ByteBuffer::new(&mut backing2);
                decoded.put(&mut buf).unwrap();
                buf.pos()
            };
            assert_eq!(&backing2[..m], &expected[..]);
        }};
    }

    #[test]
    fn aarq_roundtrip() {
        let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        aarq.user_information = Some(b"\xDE\xAD\xBE\xEF");
        roundtrip!(aarq, AARQapdu::get);
    }

    #[test]
    fn aarq_tag() {
        let aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        let mut backing = [0u8; 4096];
        let mut buf = ByteBuffer::new(&mut backing);
        aarq.put(&mut buf).unwrap();
        let bytes = buf.extract();
        assert_eq!(bytes[0], 0x60); // [APPLICATION 0] constructed
        assert_eq!(bytes[2], 0xA1); // [1] EXPLICIT
    }

    #[test]
    fn aare_roundtrip() {
        let aare = AAREapdu {
            protocol_version: None,
            application_context_name: ApplicationContextName::LogicalNameNoCiphering,
            result: 0,
            result_source_diagnostic: 1,
            responding_ap_title: None,
            responding_ae_qualifier: None,
            responding_ap_invocation_id: None,
            responding_ae_invocation_id: None,
            responder_acse_requirements: None,
            mechanism_name: None,
            responding_authentication_value: None,
            implementation_information: None,
            user_information: Some(b"\x01\x02\x03"),
        };
        roundtrip!(aare, AAREapdu::get);
    }

    #[test]
    fn rlrq_rlre_roundtrip() {
        for apdu in [
            ACSEApdu::Rlrq(RLRQapdu {
                reason: Some(0),
                user_information: Some(b"\x09\x08\x07"),
            }),
            ACSEApdu::Rlre(RLREapdu {
                reason: Some(1),
                user_information: None,
            }),
        ] {
            roundtrip!(apdu, ACSEApdu::get);
        }
    }

    #[test]
    fn acse_oid_enums() {
        let ctx = ApplicationContextName::LogicalNameNoCiphering;
        assert_eq!(ctx.to_arcs(), [2u64, 16, 756, 5, 8, 1, 1]);
        assert_eq!(ApplicationContextName::from_arcs(&ctx.to_arcs()).unwrap(), ctx);

        let unknown = ApplicationContextName::from_arcs(&[2u64, 16, 756, 5, 8, 1, 99]).unwrap();
        assert_eq!(unknown, ApplicationContextName::Unknown(99));

        // Trailing arc must fit in a single base-128 octet (<= 127).
        assert!(ApplicationContextName::from_arcs(&[2u64, 16, 756, 5, 8, 1, 128]).is_err());
        assert!(MechanismName::from_arcs(&[2u64, 16, 756, 5, 8, 2, 200]).is_err());

        let mech = MechanismName::LowLevelSecurity;
        assert_eq!(mech.to_arcs(), [2u64, 16, 756, 5, 8, 2, 1]);
        assert_eq!(MechanismName::from_arcs(&mech.to_arcs()).unwrap(), mech);

        let lowest = MechanismName::LowestLevelSecurity;
        assert_eq!(lowest.to_arcs(), [2u64, 16, 756, 5, 8, 2, 0]);
        assert_eq!(MechanismName::from_arcs(&lowest.to_arcs()).unwrap(), lowest);

        assert!(ApplicationContextName::from_arcs(&[1u64, 2, 840, 10008, 1, 1]).is_err());
        assert!(ApplicationContextName::from_arcs(&[2u64, 16, 756, 5, 8, 2, 1]).is_err());
        assert!(ApplicationContextName::from_arcs(&[2u64, 16, 756, 5, 8, 1]).is_err());
    }

    #[test]
    fn acse_unknown_roundtrip() {
        let mut aarq = AARQapdu::new(ApplicationContextName::Unknown(99));
        aarq.mechanism_name = Some(MechanismName::Unknown(100));
        roundtrip!(aarq, AARQapdu::get);
    }

    #[test]
    fn acse_oid_content_bytes() {
        // { 2 16 756 5 8 1 1 } encodes as 60 85 74 05 08 01 01.
        let mut backing = [0u8; 16];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            ApplicationContextName::LogicalNameNoCiphering
                .put_content(&mut buf)
                .unwrap()
        };
        assert_eq!(n, 7);
        assert_eq!(&backing[..7], &[0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]);

        let decoded =
            ApplicationContextName::from_content(&[0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01])
                .unwrap();
        assert_eq!(decoded, ApplicationContextName::LogicalNameNoCiphering);

        // Trailing arc > 127 rejected.
        assert!(
            ApplicationContextName::from_content(&[0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x80])
                .is_err()
        );
        // Wrong discriminator rejected.
        assert!(
            ApplicationContextName::from_content(&[0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01])
                .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // Green Book test vectors (DLMS UA 1000-2 Ed. 10)
    // -----------------------------------------------------------------------

    fn check_aarq(aarq: &AARQapdu<'_>, expected: &[u8]) {
        let mut backing = [0u8; 512];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            aarq.put(&mut buf).unwrap();
            buf.pos()
        };
        assert_eq!(&backing[..n], expected, "AARQ encoding mismatch");
        let mut r = Reader::new(expected);
        let decoded = AARQapdu::get(&mut r).unwrap();
        assert_eq!(&decoded, aarq, "AARQ decoding mismatch");
    }

    // sender-acse-requirements: BIT STRING { authentication (0) }, 7 unused bits.
    const ACSE_REQUIREMENTS: &[u8] = &[0x07, 0x80];
    const LLS_PASSWORD: &[u8] = b"12345678";
    const HLS_CHALLENGE: &[u8] = b"K56iVagY";
    const LN_INITIATE: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0,
    ];
    const SN_INITIATE: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x1C, 0x03, 0x20, 0x04, 0xB0,
    ];

    fn make_aarq<'a>(
        context: ApplicationContextName,
        mechanism: Option<MechanismName>,
        auth: Option<&'a [u8]>,
        user_info: &'a [u8],
    ) -> AARQapdu<'a> {
        let mut aarq = AARQapdu::new(context);
        if let Some(m) = mechanism {
            aarq.sender_acse_requirements = Some(ACSE_REQUIREMENTS);
            aarq.mechanism_name = Some(m);
            aarq.calling_authentication_value = auth;
        }
        aarq.user_information = Some(user_info);
        aarq
    }

    fn check_aare(aare: &AAREapdu<'_>, expected: &[u8]) {
        let mut backing = [0u8; 512];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            aare.put(&mut buf).unwrap();
            buf.pos()
        };
        assert_eq!(&backing[..n], expected, "AARE encoding mismatch");
        let mut r = Reader::new(expected);
        let decoded = AAREapdu::get(&mut r).unwrap();
        assert_eq!(&decoded, aare, "AARE decoding mismatch");
    }

    // AARE user-information: xDLMS InitiateResponse (LN/SN) and
    // ConfirmedServiceError.
    const LN_INITIATE_RESPONSE: &[u8] = &[
        0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x50, 0x1F, 0x01, 0xF4, 0x00, 0x07,
    ];
    const SN_INITIATE_RESPONSE: &[u8] = &[
        0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x1C, 0x03, 0x20, 0x01, 0xF4, 0xFA, 0x00,
    ];
    const CONFIRMED_SERVICE_ERROR: &[u8] = &[0x0E, 0x01, 0x06, 0x01];
    const HLS_CHALLENGE_RESPONSE: &[u8] = b"P6wRJ21F";

    fn make_aare<'a>(
        context: ApplicationContextName,
        result: i64,
        result_source_diagnostic: i64,
        mechanism: Option<MechanismName>,
        auth: Option<&'a [u8]>,
        user_info: Option<&'a [u8]>,
    ) -> AAREapdu<'a> {
        let mut aare = AAREapdu {
            protocol_version: None,
            application_context_name: context,
            result,
            result_source_diagnostic,
            responding_ap_title: None,
            responding_ae_qualifier: None,
            responding_ap_invocation_id: None,
            responding_ae_invocation_id: None,
            responder_acse_requirements: None,
            mechanism_name: None,
            responding_authentication_value: None,
            implementation_information: None,
            user_information: None,
        };
        if let Some(m) = mechanism {
            aare.responder_acse_requirements = Some(ACSE_REQUIREMENTS);
            aare.mechanism_name = Some(m);
            aare.responding_authentication_value = auth;
        }
        aare.user_information = user_info;
        aare
    }

    #[test]
    fn aarq_table119() {
        let lls = MechanismName::LowLevelSecurity; // { ... 2 1 }
        let hls = MechanismName::HighLevelSecurityGmac; // { ... 2 5 }

        let cases: &[(
            &[u8],
            ApplicationContextName,
            Option<MechanismName>,
            Option<&[u8]>,
            &[u8],
        )] = &[
            (
                &[
                    0x60, 0x1D, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
                    0xBE, 0x10, 0x04, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00,
                    0x00, 0x7E, 0x1F, 0x04, 0xB0,
                ],
                ApplicationContextName::LogicalNameNoCiphering,
                None,
                None,
                LN_INITIATE,
            ),
            (
                &[
                    0x60, 0x36, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
                    0x8A, 0x02, 0x07, 0x80, 0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01,
                    0xAC, 0x0A, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0xBE,
                    0x10, 0x04, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00,
                    0x7E, 0x1F, 0x04, 0xB0,
                ],
                ApplicationContextName::LogicalNameNoCiphering,
                Some(lls),
                Some(LLS_PASSWORD),
                LN_INITIATE,
            ),
            (
                &[
                    0x60, 0x36, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
                    0x8A, 0x02, 0x07, 0x80, 0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x05,
                    0xAC, 0x0A, 0x80, 0x08, 0x4B, 0x35, 0x36, 0x69, 0x56, 0x61, 0x67, 0x59, 0xBE,
                    0x10, 0x04, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00,
                    0x7E, 0x1F, 0x04, 0xB0,
                ],
                ApplicationContextName::LogicalNameNoCiphering,
                Some(hls),
                Some(HLS_CHALLENGE),
                LN_INITIATE,
            ),
            (
                &[
                    0x60, 0x1D, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x02,
                    0xBE, 0x10, 0x04, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00,
                    0x1C, 0x03, 0x20, 0x04, 0xB0,
                ],
                ApplicationContextName::ShortNameNoCiphering,
                None,
                None,
                SN_INITIATE,
            ),
            (
                &[
                    0x60, 0x36, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x02,
                    0x8A, 0x02, 0x07, 0x80, 0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01,
                    0xAC, 0x0A, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0xBE,
                    0x10, 0x04, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x1C,
                    0x03, 0x20, 0x04, 0xB0,
                ],
                ApplicationContextName::ShortNameNoCiphering,
                Some(lls),
                Some(LLS_PASSWORD),
                SN_INITIATE,
            ),
            (
                &[
                    0x60, 0x36, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x02,
                    0x8A, 0x02, 0x07, 0x80, 0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x05,
                    0xAC, 0x0A, 0x80, 0x08, 0x4B, 0x35, 0x36, 0x69, 0x56, 0x61, 0x67, 0x59, 0xBE,
                    0x10, 0x04, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x1C,
                    0x03, 0x20, 0x04, 0xB0,
                ],
                ApplicationContextName::ShortNameNoCiphering,
                Some(hls),
                Some(HLS_CHALLENGE),
                SN_INITIATE,
            ),
        ];

        for (bytes, context, mechanism, auth, user_info) in cases {
            let aarq = make_aarq(*context, *mechanism, *auth, user_info);
            check_aarq(&aarq, bytes);
        }
    }

    #[test]
    fn aarq_table124() {
        // Ciphered AARQ (LN, ciphering): application-context-name { ... 1 3 },
        // calling-AP-title [6] EXPLICIT OCTET STRING, sender-acse-requirements,
        // mechanism-name (low-level-security, arc 1), calling-authentication-value,
        // ciphered user-information (50 octets).
        let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameCiphering);
        aarq.calling_ap_title = Some(&[0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E]);
        aarq.sender_acse_requirements = Some(ACSE_REQUIREMENTS);
        aarq.mechanism_name = Some(MechanismName::LowLevelSecurity);
        aarq.calling_authentication_value = Some(LLS_PASSWORD);
        aarq.user_information = Some(&[
            0x21, 0x30, 0x30, 0x01, 0x23, 0x45, 0x67, 0x80, 0x13, 0x02, 0xFF, 0x8A, 0x78, 0x74,
            0x13, 0x3D, 0x41, 0x4C, 0xED, 0x25, 0xB4, 0x25, 0x34, 0xD2, 0x8D, 0xB0, 0x04, 0x77,
            0x20, 0x60, 0x6B, 0x17, 0x5B, 0xD5, 0x22, 0x11, 0xBE, 0x68, 0x41, 0xDB, 0x20, 0x4D,
            0x39, 0xEE, 0x6F, 0xDB, 0x8E, 0x35, 0x68, 0x55,
        ]);

        let expected: &[u8] = &[
            0x60, 0x66, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x03, 0xA6,
            0x0A, 0x04, 0x08, 0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E, 0x8A, 0x02, 0x07,
            0x80, 0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01, 0xAC, 0x0A, 0x80, 0x08,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0xBE, 0x34, 0x04, 0x32, 0x21, 0x30,
            0x30, 0x01, 0x23, 0x45, 0x67, 0x80, 0x13, 0x02, 0xFF, 0x8A, 0x78, 0x74, 0x13, 0x3D,
            0x41, 0x4C, 0xED, 0x25, 0xB4, 0x25, 0x34, 0xD2, 0x8D, 0xB0, 0x04, 0x77, 0x20, 0x60,
            0x6B, 0x17, 0x5B, 0xD5, 0x22, 0x11, 0xBE, 0x68, 0x41, 0xDB, 0x20, 0x4D, 0x39, 0xEE,
            0x6F, 0xDB, 0x8E, 0x35, 0x68, 0x55,
        ];
        check_aarq(&aarq, expected);
    }

    #[test]
    fn aare_result_source_diagnostic() {
        // Verify the result-source-diagnostic CHOICE encoding:
        // [3] EXPLICIT { acse-service-user [1] EXPLICIT INTEGER }.
        let aare = AAREapdu {
            protocol_version: None,
            application_context_name: ApplicationContextName::LogicalNameNoCiphering,
            result: 0,
            result_source_diagnostic: 0,
            responding_ap_title: None,
            responding_ae_qualifier: None,
            responding_ap_invocation_id: None,
            responding_ae_invocation_id: None,
            responder_acse_requirements: None,
            mechanism_name: None,
            responding_authentication_value: None,
            implementation_information: None,
            user_information: None,
        };
        let mut backing = [0u8; 128];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            aare.put(&mut buf).unwrap();
            buf.pos()
        };
        assert_eq!(
            &backing[..n],
            &[
                0x61, 0x17, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
                0xA2, 0x03, 0x02, 0x01, 0x00, 0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00,
            ]
        );
    }

    #[test]
    fn aare_table120() {
        let hls = MechanismName::HighLevelSecurityGmac; // { ... 2 5 }

        let cases: &[(
            &[u8],
            ApplicationContextName,
            i64,
            i64,
            Option<MechanismName>,
            Option<&[u8]>,
            Option<&[u8]>,
        )] = &[
            // No sec./LLS success (LN).
            (
                &[
                    0x61, 0x29, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
                    0xA2, 0x03, 0x02, 0x01, 0x00, 0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00, 0xBE,
                    0x10, 0x04, 0x0E, 0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x50, 0x1F,
                    0x01, 0xF4, 0x00, 0x07,
                ],
                ApplicationContextName::LogicalNameNoCiphering,
                0,
                0,
                None,
                None,
                Some(LN_INITIATE_RESPONSE),
            ),
            // No sec./LLS failure 1 (LN): application-context-name not supported.
            (
                &[
                    0x61, 0x29, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
                    0xA2, 0x03, 0x02, 0x01, 0x01, 0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x02, 0xBE,
                    0x10, 0x04, 0x0E, 0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x50, 0x1F,
                    0x01, 0xF4, 0x00, 0x07,
                ],
                ApplicationContextName::LogicalNameNoCiphering,
                1,
                2,
                None,
                None,
                Some(LN_INITIATE_RESPONSE),
            ),
            // No sec./LLS failure 2 (LN): ConfirmedServiceError, dlms-version-too-low.
            (
                &[
                    0x61, 0x1F, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
                    0xA2, 0x03, 0x02, 0x01, 0x01, 0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x01, 0xBE,
                    0x06, 0x04, 0x04, 0x0E, 0x01, 0x06, 0x01,
                ],
                ApplicationContextName::LogicalNameNoCiphering,
                1,
                1,
                None,
                None,
                Some(CONFIRMED_SERVICE_ERROR),
            ),
            // HLS success (LN): authentication required, GMAC challenge response.
            (
                &[
                    0x61, 0x42, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
                    0xA2, 0x03, 0x02, 0x01, 0x00, 0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x0E, 0x88,
                    0x02, 0x07, 0x80, 0x89, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x05, 0xAA,
                    0x0A, 0x80, 0x08, 0x50, 0x36, 0x77, 0x52, 0x4A, 0x32, 0x31, 0x46, 0xBE, 0x10,
                    0x04, 0x0E, 0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x50, 0x1F, 0x01,
                    0xF4, 0x00, 0x07,
                ],
                ApplicationContextName::LogicalNameNoCiphering,
                0,
                14,
                Some(hls),
                Some(HLS_CHALLENGE_RESPONSE),
                Some(LN_INITIATE_RESPONSE),
            ),
            // No sec./LLS success (SN).
            (
                &[
                    0x61, 0x29, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x02,
                    0xA2, 0x03, 0x02, 0x01, 0x00, 0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00, 0xBE,
                    0x10, 0x04, 0x0E, 0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x1C, 0x03, 0x20,
                    0x01, 0xF4, 0xFA, 0x00,
                ],
                ApplicationContextName::ShortNameNoCiphering,
                0,
                0,
                None,
                None,
                Some(SN_INITIATE_RESPONSE),
            ),
            // HLS success (SN).
            (
                &[
                    0x61, 0x42, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x02,
                    0xA2, 0x03, 0x02, 0x01, 0x00, 0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x0E, 0x88,
                    0x02, 0x07, 0x80, 0x89, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x05, 0xAA,
                    0x0A, 0x80, 0x08, 0x50, 0x36, 0x77, 0x52, 0x4A, 0x32, 0x31, 0x46, 0xBE, 0x10,
                    0x04, 0x0E, 0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x1C, 0x03, 0x20, 0x01, 0xF4, 0xFA, 0x00,
                ],
                ApplicationContextName::ShortNameNoCiphering,
                0,
                14,
                Some(hls),
                Some(HLS_CHALLENGE_RESPONSE),
                Some(SN_INITIATE_RESPONSE),
            ),
        ];

        for (bytes, context, result, diag, mechanism, auth, user_info) in cases {
            let aare = make_aare(*context, *result, *diag, *mechanism, *auth, *user_info);
            check_aare(&aare, bytes);
        }
    }
}
