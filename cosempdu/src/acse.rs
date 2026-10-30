//! ACSE (Association Control Service Element) APDUs, BER encoded.
//!
//! Mirrors `src/COSEMpdu/acse.py`: AARQ/AARE/RLRQ/RLRE APDUs used during
//! DLMS/COSEM association establishment and release. Encoding follows X.690
//! with explicit/implicit context tagging.

use crate::ber::{decode_signed, decode_u8, put_signed, put_tlv, put_u8, with_content};
use bytebuffer::{ByteBuffer, Reader};
use crate::error::{Error, Result};
use crate::x680::{Class, Tag, UniversalTag};
use crate::x690::{Length};

const fn ctx(number: u8, constructed: bool) -> Tag {
    Tag {
        class: Class::Context,
        number,
        constructed,
    }
}

const fn app(number: u8) -> Tag {
    Tag {
        class: Class::Application,
        number,
        constructed: true,
    }
}

/// Read one TLV header (tag + length) without checking the tag. Returns
/// `(tag, content_length)`; the reader is left positioned at the content start.
fn read_tlv_any(buf: &mut Reader<'_>) -> Result<(Tag, usize)> {
    let tag = Tag::get(buf)?;
    let length = Length::get(buf)?;
    if length.value < 0 {
        return Err(Error::Unsupported {
            what: "indefinite length in ACSE",
        });
    }
    Ok((tag, length.value as usize))
}

/// Read one TLV header and verify its tag equals `expected`. Returns the
/// content length; the reader is left positioned at the content start.
fn read_tl(buf: &mut Reader<'_>, expected: Tag) -> Result<usize> {
    let (tag, len) = read_tlv_any(buf)?;
    if tag != expected {
        return Err(Error::Message("unexpected tag"));
    }
    Ok(len)
}

/// Read a TLV whose content must fit entirely within `end` (the enclosing
/// `[APPLICATION n] IMPLICIT SEQUENCE` boundary).
fn read_tlv_bounded(buf: &mut Reader<'_>, end: usize) -> Result<(Tag, usize)> {
    let (tag, len) = read_tlv_any(buf)?;
    if buf.pos() + len > end {
        return Err(Error::Message("TLV overruns enclosing SEQUENCE"));
    }
    Ok((tag, len))
}

/// Peek the tag number of the next field without consuming it. ACSE field tags
/// are single-octet context tags (numbers < 31), so the number is the low 5 bits.
fn peek_field_number(buf: &mut Reader<'_>) -> Result<u8> {
    let byte = buf.peek(1)?[0];
    Ok(byte & 0x1F)
}

/// Decode the inner TLV of an EXPLICIT field. `buf` is positioned at the start
/// of the inner TLV and `len` is the EXPLICIT content length. Returns
/// `(inner_tag, inner_content_length)`; errors if the inner TLV does not
/// exactly fill the EXPLICIT content.
fn unwrap_explicit(buf: &mut Reader<'_>, len: usize) -> Result<(Tag, usize)> {
    let start = buf.pos();
    let (tag, inner_len) = read_tlv_any(buf)?;
    if buf.pos() - start + inner_len != len {
        return Err(Error::Message("trailing data in explicit field"));
    }
    Ok((tag, inner_len))
}

fn put_explicit_oid(
    buf: &mut ByteBuffer<'_>,
    number: u8,
    value: &ApplicationContextName,
) -> Result<usize> {
    with_content(buf, &ctx(number, true), |b| {
        with_content(b, &Tag::universal(UniversalTag::ObjectIdentifier), |ib| {
            value.put(ib)
        })
    })
}

fn put_explicit_octet_string(
    buf: &mut ByteBuffer<'_>,
    number: u8,
    bytes: &[u8],
) -> Result<usize> {
    with_content(buf, &ctx(number, true), |b| {
        put_tlv(b, &Tag::universal(UniversalTag::OctetString), bytes)
    })
}

fn put_explicit_integer(buf: &mut ByteBuffer<'_>, number: u8, value: i64) -> Result<usize> {
    with_content(buf, &ctx(number, true), |b| {
        with_content(b, &Tag::universal(UniversalTag::Integer), |ib| {
            put_signed(ib, value)
        })
    })
}

fn put_explicit_u8(buf: &mut ByteBuffer<'_>, number: u8, value: u8) -> Result<usize> {
    with_content(buf, &ctx(number, true), |b| {
        with_content(b, &Tag::universal(UniversalTag::Integer), |ib| {
            Ok(ib.put_u8(value)?)
        })
    })
}


fn put_implicit_integer(buf: &mut ByteBuffer<'_>, number: u8, value: i64) -> Result<usize> {
    with_content(buf, &ctx(number, false), |b| put_signed(b, value))
}

fn put_implicit_bit_string(
    buf: &mut ByteBuffer<'_>,
    number: u8,
    content: &[u8],
) -> Result<usize> {
    put_tlv(buf, &ctx(number, false), content)
}

/// Encode an EXPLICIT `Authentication-value` whose chosen alternative is
/// `charstring [0] IMPLICIT GraphicString`: `<ctx(n,true)><len> 80 <len> <bytes>`.
fn put_explicit_charstring(
    buf: &mut ByteBuffer<'_>,
    number: u8,
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
fn put_implicit_oid(buf: &mut ByteBuffer<'_>, number: u8, value: &MechanismName) -> Result<usize> {
    with_content(buf, &ctx(number, false), |b| value.put_content(b))
}

/// DLMS/COSEM `application-context-name` (`{ 2 16 756 5 8 1 X }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApplicationContextName {
    /// Logical-name referencing, no ciphering (`{ 2 16 756 5 8 1 1 }`).
    LogicalNameNoCiphering = 1,
    /// Short-name referencing, no ciphering (`{ 2 16 756 5 8 1 2 }`).
    ShortNameNoCiphering = 2,
    /// Logical-name referencing, with ciphering (`{ 2 16 756 5 8 1 3 }`).
    LogicalNameCiphering = 3,
    /// Short-name referencing, with ciphering (`{ 2 16 756 5 8 1 4 }`).
    ShortNameCiphering = 4,
}

impl ApplicationContextName {
    /// The full seven arcs `{ 2 16 756 5 8 1 X }`.
    pub fn to_arcs(self) -> [u64; 7] {
        let mut arcs = [0u64; 7];
        arcs[..5].copy_from_slice(&ACSE_OID_PREFIX);
        arcs[5] = 1;
        arcs[6] = self as u8 as u64;
        arcs
    }

    /// Map a trailing arc to the variant, rejecting unknown values.
    fn from_trailing(x: u8) -> Result<Self> {
        match x {
            1 => Ok(ApplicationContextName::LogicalNameNoCiphering),
            2 => Ok(ApplicationContextName::ShortNameNoCiphering),
            3 => Ok(ApplicationContextName::LogicalNameCiphering),
            4 => Ok(ApplicationContextName::ShortNameCiphering),
            _ => Err(Error::InvalidAcseOid),
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
        Self::from_trailing(arcs[6] as u8)
    }

    /// Write the raw base-128 OBJECT IDENTIFIER content (no tag) into `buf`.
    ///
    /// The content is always exactly seven octets: the fixed prefix
    /// `{ 2 16 756 5 8 }`, the context discriminator `1`, and the trailing arc
    /// `X` (a single octet since `X <= 127`).
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        buf.write(&ACSE_OID_PREFIX_CONTENT)?;
        buf.put_u8(CONTEXT_DISCRIMINATOR)?;
        buf.put_u8(*self as u8)?;
        Ok(7)
    }

    /// Decode the raw base-128 OBJECT IDENTIFIER content (no tag) directly,
    /// without materializing an intermediate arc array.
    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        let content = buf.read(7)?;
        if content[..5] != ACSE_OID_PREFIX_CONTENT[..]
            || content[5] != CONTEXT_DISCRIMINATOR
            || content[6] > 127
        {
            return Err(Error::InvalidAcseOid);
        }
        Self::from_trailing(content[6])
    }
}

/// DLMS/COSEM `mechanism-name` (`{ 2 16 756 5 8 2 X }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MechanismName {
    /// Lowest level security, no authentication (`{ 2 16 756 5 8 2 0 }`).
    LowestLevelSecurity = 0,
    /// Low-level security, LLS (`{ 2 16 756 5 8 2 1 }`).
    LowLevelSecurity = 1,
    /// High-level security (`{ 2 16 756 5 8 2 2 }`).
    HighLevelSecurity = 2,
    /// High-level security, MD5 (`{ 2 16 756 5 8 2 3 }`).
    HighLevelSecurityMd5 = 3,
    /// High-level security, SHA-1 (`{ 2 16 756 5 8 2 4 }`).
    HighLevelSecuritySha1 = 4,
    /// High-level security, GMAC (`{ 2 16 756 5 8 2 5 }`).
    HighLevelSecurityGmac = 5,
    /// High-level security, SHA-256 (`{ 2 16 756 5 8 2 6 }`).
    HighLevelSecuritySha256 = 6,
    /// High-level security, ECDSA (`{ 2 16 756 5 8 2 7 }`).
    HighLevelSecurityEcdsa = 7,
}

impl MechanismName {
    /// The full seven arcs `{ 2 16 756 5 8 2 X }`.
    pub fn to_arcs(self) -> [u64; 7] {
        let mut arcs = [0u64; 7];
        arcs[..5].copy_from_slice(&ACSE_OID_PREFIX);
        arcs[5] = 2;
        arcs[6] = self as u8 as u64;
        arcs
    }

    /// Map a trailing arc to the variant, rejecting unknown values.
    fn from_trailing(x: u8) -> Result<Self> {
        match x {
            0 => Ok(MechanismName::LowestLevelSecurity),
            1 => Ok(MechanismName::LowLevelSecurity),
            2 => Ok(MechanismName::HighLevelSecurity),
            3 => Ok(MechanismName::HighLevelSecurityMd5),
            4 => Ok(MechanismName::HighLevelSecuritySha1),
            5 => Ok(MechanismName::HighLevelSecurityGmac),
            6 => Ok(MechanismName::HighLevelSecuritySha256),
            7 => Ok(MechanismName::HighLevelSecurityEcdsa),
            _ => Err(Error::InvalidAcseOid),
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
        Self::from_trailing(arcs[6] as u8)
    }

    /// Write the raw base-128 OBJECT IDENTIFIER content (no tag) into `buf`.
    ///
    /// The content is always exactly seven octets: the fixed prefix
    /// `{ 2 16 756 5 8 }`, the mechanism discriminator `2`, and the trailing
    /// arc `X` (a single octet since `X <= 127`).
    pub fn put_content(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        buf.write(&ACSE_OID_PREFIX_CONTENT)?;
        buf.put_u8(MECHANISM_DISCRIMINATOR)?;
        buf.put_u8(*self as u8)?;
        Ok(7)
    }

    /// Decode the raw base-128 OBJECT IDENTIFIER content (no tag) directly,
    /// without materializing an intermediate arc array.
    pub fn from_content(buf: &mut Reader<'_>) -> Result<Self> {
        let content = buf.read(7)?;
        if content[..5] != ACSE_OID_PREFIX_CONTENT[..]
            || content[5] != MECHANISM_DISCRIMINATOR
            || content[6] > 127
        {
            return Err(Error::InvalidAcseOid);
        }
        Self::from_trailing(content[6])
    }
}

/// `Association-result ::= INTEGER { accepted (0), rejected-permanent (1), rejected-transient (2) }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AssociationResult {
    /// accepted (0).
    Accepted = 0,
    /// rejected-permanent (1).
    RejectedPermanent = 1,
    /// rejected-transient (2).
    RejectedTransient = 2,
}

impl AssociationResult {
    /// Encode as `result [2] Association-result` (EXPLICIT INTEGER).
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        put_explicit_u8(buf, 2, *self as u8)
    }

    /// Decode the `result [2] Association-result` field content.
    pub fn get(buf: &mut Reader<'_>, len: usize) -> Result<Self> {
        let (_itag, inner_len) = unwrap_explicit(buf, len)?;
        match decode_u8(buf.read(inner_len)?)? {
            0 => Ok(AssociationResult::Accepted),
            1 => Ok(AssociationResult::RejectedPermanent),
            2 => Ok(AssociationResult::RejectedTransient),
            err => Err(Error::WrongAssociationResult{actual: err}),
        }
    }
}

/// `acse-service-user [1] INTEGER` — one alternative of `Associate-source-diagnostic`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AcseServiceUser {
    /// null (0).
    Null = 0,
    /// no-reason-given (1).
    NoReasonGiven = 1,
    /// application-context-name-not-supported (2).
    ApplicationContextNameNotSupported = 2,
    /// calling-AP-title-not-recognized (3).
    CallingApTitleNotRecognized = 3,
    /// calling-AP-invocation-identifier-not-recognized (4).
    CallingApInvocationIdentifierNotRecognized = 4,
    /// calling-AE-qualifier-not-recognized (5).
    CallingAeQualifierNotRecognized = 5,
    /// calling-AE-invocation-identifier-not-recognized (6).
    CallingAeInvocationIdentifierNotRecognized = 6,
    /// called-AP-title-not-recognized (7).
    CalledApTitleNotRecognized = 7,
    /// called-AP-invocation-identifier-not-recognized (8).
    CalledApInvocationIdentifierNotRecognized = 8,
    /// called-AE-qualifier-not-recognized (9).
    CalledAeQualifierNotRecognized = 9,
    /// called-AE-invocation-identifier-not-recognized (10).
    CalledAeInvocationIdentifierNotRecognized = 10,
    /// authentication-mechanism-name-not-recognised (11).
    AuthenticationMechanismNameNotRecognised = 11,
    /// authentication-mechanism-name-required (12).
    AuthenticationMechanismNameRequired = 12,
    /// authentication-failure (13).
    AuthenticationFailure = 13,
    /// authentication-required (14).
    AuthenticationRequired = 14,
}

impl AcseServiceUser {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(AcseServiceUser::Null),
            1 => Ok(AcseServiceUser::NoReasonGiven),
            2 => Ok(AcseServiceUser::ApplicationContextNameNotSupported),
            3 => Ok(AcseServiceUser::CallingApTitleNotRecognized),
            4 => Ok(AcseServiceUser::CallingApInvocationIdentifierNotRecognized),
            5 => Ok(AcseServiceUser::CallingAeQualifierNotRecognized),
            6 => Ok(AcseServiceUser::CallingAeInvocationIdentifierNotRecognized),
            7 => Ok(AcseServiceUser::CalledApTitleNotRecognized),
            8 => Ok(AcseServiceUser::CalledApInvocationIdentifierNotRecognized),
            9 => Ok(AcseServiceUser::CalledAeQualifierNotRecognized),
            10 => Ok(AcseServiceUser::CalledAeInvocationIdentifierNotRecognized),
            11 => Ok(AcseServiceUser::AuthenticationMechanismNameNotRecognised),
            12 => Ok(AcseServiceUser::AuthenticationMechanismNameRequired),
            13 => Ok(AcseServiceUser::AuthenticationFailure),
            14 => Ok(AcseServiceUser::AuthenticationRequired),
            _ => Err(Error::Message("unknown acse-service-user diagnostic")),
        }
    }
}

/// `acse-service-provider [2] INTEGER` — one alternative of `Associate-source-diagnostic`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AcseServiceProvider {
    /// null (0).
    Null = 0,
    /// no-reason-given (1).
    NoReasonGiven = 1,
    /// no-common-acse-version (2).
    NoCommonAcseVersion = 2,
}

impl AcseServiceProvider {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(AcseServiceProvider::Null),
            1 => Ok(AcseServiceProvider::NoReasonGiven),
            2 => Ok(AcseServiceProvider::NoCommonAcseVersion),
            _ => Err(Error::Message("unknown acse-service-provider diagnostic")),
        }
    }
}

/// `Associate-source-diagnostic ::= CHOICE { acse-service-user [1], acse-service-provider [2] }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociateSourceDiagnostic {
    ServiceUser(AcseServiceUser),
    ServiceProvider(AcseServiceProvider),
}

impl AssociateSourceDiagnostic {
    /// Encode as `result-source-diagnostic [3] EXPLICIT` CHOICE.
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        with_content(buf, &ctx(3, true), |b| match self {
            AssociateSourceDiagnostic::ServiceUser(v) => put_explicit_u8(b, 1, *v as u8),
            AssociateSourceDiagnostic::ServiceProvider(v) => put_explicit_u8(b, 2, *v as u8)
        })
    }

    /// Decode the `result-source-diagnostic [3]` field content.
    pub fn get(buf: &mut Reader<'_>, len: usize) -> Result<Self> {
        let (alt, alt_len) = unwrap_explicit(buf, len)?;
        let (_int, int_len) = unwrap_explicit(buf, alt_len)?;
        let value = decode_u8(buf.read(int_len)?)?;
        match alt.number {
            1 => Ok(AssociateSourceDiagnostic::ServiceUser(
                AcseServiceUser::from_u8(value)?,
            )),
            2 => Ok(AssociateSourceDiagnostic::ServiceProvider(
                AcseServiceProvider::from_u8(value)?,
            )),
            _ => Err(Error::Message("unknown Associate-source-diagnostic alternative")),
        }
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
    const TAG: Tag = app(0);

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
        with_content(buf, &Self::TAG, |b| {
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
        let len = read_tl(buf, Self::TAG)?;
        let end = buf.pos() + len;
        let mut apdu = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        let mut application_context_name = None;
        while buf.pos() < end {
            let (ftag, flen) = read_tlv_bounded(buf, end)?;
            match ftag.number {
                0 => apdu.protocol_version = Some(buf.read(flen)?),
                1 => {
                    let (_itag, _) = unwrap_explicit(buf, flen)?;
                    application_context_name =
                        Some(ApplicationContextName::get(buf)?);
                }
                2 => {
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    apdu.called_ap_title = Some(buf.read(olen)?);
                }
                3 => {
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    apdu.called_ae_qualifier = Some(buf.read(olen)?);
                }
                4 => apdu.called_ap_invocation_id = Some(decode_signed(buf.read(flen)?)?),
                5 => apdu.called_ae_invocation_id = Some(decode_signed(buf.read(flen)?)?),
                6 => {
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    apdu.calling_ap_title = Some(buf.read(olen)?);
                }
                7 => {
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    apdu.calling_ae_qualifier = Some(buf.read(olen)?);
                }
                8 => apdu.calling_ap_invocation_id = Some(decode_signed(buf.read(flen)?)?),
                9 => apdu.calling_ae_invocation_id = Some(decode_signed(buf.read(flen)?)?),
                10 => apdu.sender_acse_requirements = Some(buf.read(flen)?),
                11 => apdu.mechanism_name = Some(MechanismName::from_content(buf)?),
                12 => {
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    apdu.calling_authentication_value = Some(buf.read(olen)?);
                }
                29 => apdu.implementation_information = Some(buf.read(flen)?),
                30 => {
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    apdu.user_information = Some(buf.read(olen)?);
                }
                _ => {
                    buf.read(flen)?;
                }
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
    pub result: AssociationResult,
    /// `result-source-diagnostic [3] Associate-source-diagnostic` (CHOICE).
    pub result_source_diagnostic: AssociateSourceDiagnostic,
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
    const TAG: Tag = app(1);

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        with_content(buf, &Self::TAG, |b| {
            let mut written = 0usize;
            if let Some(pv) = &self.protocol_version {
                written += put_implicit_bit_string(b, 0, pv)?;
            }
            written += put_explicit_oid(b, 1, &self.application_context_name)?;
            written += self.result.put(b)?;
            // result-source-diagnostic [3] EXPLICIT Associate-source-diagnostic.
            written += self.result_source_diagnostic.put(b)?;
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
        let len = read_tl(buf, Self::TAG)?;
        let end = buf.pos() + len;
        let mut protocol_version = None;
        let mut application_context_name = None;
        let mut result = AssociationResult::Accepted;
        let mut result_source_diagnostic =
            AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::Null);
        let mut responding_ap_title = None;
        let mut responding_ae_qualifier = None;
        let mut responding_ap_invocation_id = None;
        let mut responding_ae_invocation_id = None;
        let mut responder_acse_requirements = None;
        let mut mechanism_name = None;
        let mut responding_authentication_value = None;
        let mut implementation_information = None;
        let mut user_information = None;
        while buf.pos() < end {
            let (ftag, flen) = read_tlv_bounded(buf, end)?;
            match ftag.number {
                0 => protocol_version = Some(buf.read(flen)?),
                1 => {
                    let (_itag, _) = unwrap_explicit(buf, flen)?;
                    application_context_name =
                        Some(ApplicationContextName::get(buf)?);
                }
                2 => {
                    result = AssociationResult::get(buf, flen)?;
                }
                3 => {
                    result_source_diagnostic = AssociateSourceDiagnostic::get(buf, flen)?;
                }
                4 => {
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    responding_ap_title = Some(buf.read(olen)?);
                }
                5 => {
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    responding_ae_qualifier = Some(buf.read(olen)?);
                }
                6 => responding_ap_invocation_id = Some(decode_signed(buf.read(flen)?)?),
                7 => responding_ae_invocation_id = Some(decode_signed(buf.read(flen)?)?),
                8 => responder_acse_requirements = Some(buf.read(flen)?),
                9 => mechanism_name = Some(MechanismName::from_content(buf)?),
                10 => {
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    responding_authentication_value = Some(buf.read(olen)?);
                }
                29 => implementation_information = Some(buf.read(flen)?),
                30 => {
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    user_information = Some(buf.read(olen)?);
                }
                _ => {
                    buf.read(flen)?;
                }
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


/// `Release-request-reason ::= INTEGER { normal (0), urgent (1), user-defined (30) }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReleaseRequestReason {
    /// normal (0).
    Normal = 0,
    /// urgent (1).
    Urgent = 1,
    /// user-defined (30).
    UserDefined = 30,
}

impl ReleaseRequestReason {
    const TAG: Tag = ctx(0, false);

    /// Encode as `reason [0] IMPLICIT Release-request-reason` (full TLV).
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        with_content(buf, &Self::TAG, |b| put_u8(b, *self as u8))
    }

    /// Decode the `reason [0] IMPLICIT Release-request-reason` field (full TLV).
    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        let len = read_tl(buf, Self::TAG)?;
        if len != 1 {
            return Err(Error::Message("release request reason must be a 1-byte INTEGER"));
        }
        match buf.get_u8()? {
            0 => Ok(Self::Normal),
            1 => Ok(Self::Urgent),
            30 => Ok(Self::UserDefined),
            _ => Err(Error::Message("unknown release request reason")),
        }
    }
}


/// `Release-response-reason ::= INTEGER { normal(0), not-finished(1), user-defined(30) }`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReleaseResponseReason {
    /// normal (0).
    Normal = 0,
    /// not-finished (1).
    NotFinished = 1,
    /// user-defined (30).
    UserDefined = 30,
}

impl ReleaseResponseReason {
    const TAG: Tag = ctx(0, false);

    /// Encode as `reason [0] IMPLICIT Release-response-reason` (full TLV).
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        with_content(buf, &Self::TAG, |b| put_u8(b, *self as u8))
    }

    /// Decode `reason [0] IMPLICIT Release-response-reason` (full TLV).
    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        let len = read_tl(buf, Self::TAG)?;
        if len != 1 {
            return Err(Error::Message("release response reason must be a 1-byte INTEGER"));
        }
        match buf.get_u8()? {
            0 => Ok(Self::Normal),
            1 => Ok(Self::NotFinished),
            30 => Ok(Self::UserDefined),
            _ => Err(Error::Message("unknown release response reason")),
        }
    }
}

/// RLRQ-apdu ::= [APPLICATION 2] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLRQapdu<'a> {
    pub reason: Option<ReleaseRequestReason>,
    pub user_information: Option<&'a [u8]>,
}

impl<'a> RLRQapdu<'a> {
    const TAG: Tag = app(2);

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        with_content(buf, &Self::TAG, |b| {
            let mut written = 0usize;
            if let Some(reason) = self.reason {
                written += reason.put(b)?;
            }
            if let Some(ui) = &self.user_information {
                written += put_explicit_octet_string(b, 30, ui)?;
            }
            Ok(written)
        })
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let len = read_tl(buf, Self::TAG)?;
        let end = buf.pos() + len;
        let mut reason = None;
        let mut user_information = None;
        while buf.pos() < end {
            match peek_field_number(buf)? {
                0 => reason = Some(ReleaseRequestReason::get(buf)?),
                30 => {
                    let (_ftag, flen) = read_tlv_bounded(buf, end)?;
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    user_information = Some(buf.read(olen)?);
                }
                _ => {
                    let (_ftag, flen) = read_tlv_bounded(buf, end)?;
                    buf.read(flen)?;
                }
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
    pub reason: Option<ReleaseResponseReason>,
    pub user_information: Option<&'a [u8]>,
}

impl<'a> RLREapdu<'a> {
    const TAG: Tag = app(3);

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        with_content(buf, &Self::TAG, |b| {
            let mut written = 0usize;
            if let Some(reason) = self.reason {
                written += reason.put(b)?;
            }
            if let Some(ui) = &self.user_information {
                written += put_explicit_octet_string(b, 30, ui)?;
            }
            Ok(written)
        })
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let len = read_tl(buf, Self::TAG)?;
        let end = buf.pos() + len;
        let mut reason = None;
        let mut user_information = None;
        while buf.pos() < end {
            match peek_field_number(buf)? {
                0 => reason = Some(ReleaseResponseReason::get(buf)?),
                30 => {
                    let (_ftag, flen) = read_tlv_bounded(buf, end)?;
                    let (_itag, olen) = unwrap_explicit(buf, flen)?;
                    user_information = Some(buf.read(olen)?);
                }
                _ => {
                    let (_ftag, flen) = read_tlv_bounded(buf, end)?;
                    buf.read(flen)?;
                }
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
        let tag = Tag::get(buf)?;
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
            result: AssociationResult::Accepted,
            result_source_diagnostic: AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::NoReasonGiven),
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
                reason: Some(ReleaseRequestReason::Normal),
                user_information: Some(b"\x09\x08\x07"),
            }),
            ACSEApdu::Rlre(RLREapdu {
                reason: Some(ReleaseResponseReason::NotFinished),
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

        // Unknown trailing arc rejected.
        assert!(ApplicationContextName::from_arcs(&[2u64, 16, 756, 5, 8, 1, 99]).is_err());

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
    fn acse_oid_content_bytes() {
        // { 2 16 756 5 8 1 1 } encodes as 60 85 74 05 08 01 01.
        let mut backing = [0u8; 16];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            ApplicationContextName::LogicalNameNoCiphering
                .put(&mut buf)
                .unwrap()
        };
        assert_eq!(n, 7);
        assert_eq!(&backing[..7], &[0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]);

        let oid = [0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01];
        let decoded = ApplicationContextName::get(&mut Reader::new(&oid)).unwrap();
        assert_eq!(decoded, ApplicationContextName::LogicalNameNoCiphering);

        // Trailing arc > 127 rejected.
        let bad = [0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x80];
        assert!(ApplicationContextName::get(&mut Reader::new(&bad)).is_err());

        // Wrong discriminator rejected.
        let bad = [0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01];
        assert!(ApplicationContextName::get(&mut Reader::new(&bad)).is_err());
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
        result: AssociationResult,
        result_source_diagnostic: AssociateSourceDiagnostic,
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
            result: AssociationResult::Accepted,
            result_source_diagnostic: AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::Null),
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
    fn associate_source_diagnostic_service_provider() {
        // result-source-diagnostic CHOICE with the acse-service-provider [2]
        // alternative: no-common-acse-version (2).
        let diag =
            AssociateSourceDiagnostic::ServiceProvider(AcseServiceProvider::NoCommonAcseVersion);
        let mut backing = [0u8; 32];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            diag.put(&mut buf).unwrap()
        };
        assert_eq!(&backing[..n], &[0xA3, 0x05, 0xA2, 0x03, 0x02, 0x01, 0x02]);

        let content = &backing[2..n];
        let decoded =
            AssociateSourceDiagnostic::get(&mut Reader::new(content), content.len()).unwrap();
        assert_eq!(decoded, diag);
    }

    #[test]
    fn associate_source_diagnostic_unknown() {
        // Unknown acse-service-user value rejected.
        let bytes = [0xA1, 0x03, 0x02, 0x01, 0x0F]; // acse-service-user [1] 15
        assert!(AssociateSourceDiagnostic::get(&mut Reader::new(&bytes), bytes.len()).is_err());

        // Unknown acse-service-provider value rejected.
        let bytes = [0xA2, 0x03, 0x02, 0x01, 0x03]; // acse-service-provider [2] 3
        assert!(AssociateSourceDiagnostic::get(&mut Reader::new(&bytes), bytes.len()).is_err());

        // Unknown CHOICE alternative tag rejected.
        let bytes = [0xA5, 0x03, 0x02, 0x01, 0x00]; // [5] EXPLICIT INTEGER
        assert!(AssociateSourceDiagnostic::get(&mut Reader::new(&bytes), bytes.len()).is_err());
    }

    #[test]
    fn aare_table120() {
        let hls = MechanismName::HighLevelSecurityGmac; // { ... 2 5 }

        let cases: &[(
            &[u8],
            ApplicationContextName,
            AssociationResult,
            AssociateSourceDiagnostic,
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
                AssociationResult::Accepted,
                AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::Null),
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
                AssociationResult::RejectedPermanent,
                AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::ApplicationContextNameNotSupported),
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
                AssociationResult::RejectedPermanent,
                AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::NoReasonGiven),
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
                AssociationResult::Accepted,
                AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::AuthenticationRequired),
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
                AssociationResult::Accepted,
                AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::Null),
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
                AssociationResult::Accepted,
                AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::AuthenticationRequired),
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
