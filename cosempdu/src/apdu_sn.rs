//! xDLMS APDU types for SN (short name) referencing (IEC 62056-5-3 /
//! DLMS Green Book 8.3, clause 8.3).
//!
//! Implements the standardised xDLMS PDUs used with no ciphering:
//! `InitiateRequest`, `ReadRequest`, `WriteRequest`, `InitiateResponse`,
//! `ReadResponse`, `WriteResponse` and `ConfirmedServiceError`, plus their
//! supporting types.

use crate::apdu::{DataAccessResult, ReaderList};
use crate::axdr::{get_length, put_length};
use crate::data::data_value;
use crate::error::{Error, Result};
use bytebuffer::{ByteBuffer, Reader};

/// `Conformance ::= [APPLICATION 31] IMPLICIT BIT STRING (SIZE(24))`.
///
/// Encoded in BER: tag (`5F 1F`) + length (`04`) + unused-bits (`00`) + 3 value
/// octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conformance(pub [u8; 3]);

impl Conformance {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.write(&[0x5F, 0x1F, 0x04, 0x00])?;
        written += buf.write(&self.0)?;
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        let t0 = buf.get_u8()?;
        let t1 = buf.get_u8()?;
        if t0 != 0x5F || t1 != 0x1F {
            return Err(Error::UnexpectedTag { name: "Conformance", actual: t0 });
        }
        let len = buf.get_u8()?;
        let unused = buf.get_u8()?;
        if len != 4 || unused != 0 {
            return Err(Error::Message("invalid Conformance bit-string header"));
        }
        let mut value = [0u8; 3];
        value.copy_from_slice(buf.read(3)?);
        Ok(Conformance(value))
    }
}

/// `ObjectName ::= Integer16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectName(pub u16);

impl ObjectName {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        Ok(buf.write(&self.0.to_be_bytes())?)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(ObjectName(u16::from_be_bytes([buf.get_u8()?, buf.get_u8()?])))
    }
}

/// `Data-Access-Result ::= ENUMERATED` codes.
pub mod data_access_result {
    pub const SUCCESS: u8 = 0;
    pub const HARDWARE_FAULT: u8 = 1;
    pub const TEMPORARY_FAILURE: u8 = 2;
    pub const READ_WRITE_DENIED: u8 = 3;
    pub const OBJECT_UNDEFINED: u8 = 4;
    pub const OBJECT_CLASS_INCONSISTENT: u8 = 9;
    pub const OBJECT_UNAVAILABLE: u8 = 11;
    pub const TYPE_UNMATCHED: u8 = 12;
    pub const SCOPE_OF_ACCESS_VIOLATED: u8 = 13;
    pub const DATA_BLOCK_UNAVAILABLE: u8 = 14;
    pub const LONG_GET_ABORTED: u8 = 15;
    pub const NO_LONG_GET_IN_PROGRESS: u8 = 16;
    pub const LONG_SET_ABORTED: u8 = 17;
    pub const NO_LONG_SET_IN_PROGRESS: u8 = 18;
    pub const DATA_BLOCK_NUMBER_INVALID: u8 = 19;
    pub const OTHER_REASON: u8 = 250;
}

fn put_presence(buf: &mut ByteBuffer<'_>, present: bool) -> Result<usize> {
    Ok(buf.put_u8(if present { 0xFF } else { 0x00 })?)
}

fn get_presence(buf: &mut Reader<'_>) -> Result<bool> {
    Ok(buf.get_u8()? != 0)
}

fn get_u16(buf: &mut Reader<'_>) -> Result<u16> {
    Ok(u16::from_be_bytes([buf.get_u8()?, buf.get_u8()?]))
}

/// `Data-Block-Result ::= SEQUENCE { last-block, block-number, raw-data }`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DataBlockResult<'a> {
    pub last_block: bool,
    pub block_number: u16,
    pub raw_data: &'a [u8],
}

impl<'a> DataBlockResult<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = put_presence(buf, self.last_block)?;
        written += buf.write(&self.block_number.to_be_bytes())?;
        written += crate::axdr::put_octet_string(buf, self.raw_data)?;
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(DataBlockResult {
            last_block: get_presence(buf)?,
            block_number: get_u16(buf)?,
            raw_data: crate::axdr::get_octet_string(buf)?,
        })
    }
}

/// `Block-Number-Access ::= SEQUENCE { block-number }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockNumberAccess {
    pub block_number: u16,
}

impl BlockNumberAccess {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        Ok(buf.write(&self.block_number.to_be_bytes())?)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(BlockNumberAccess { block_number: get_u16(buf)? })
    }
}

/// `Read-Data-Block-Access ::= SEQUENCE { last-block, block-number, raw-data }`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadDataBlockAccess<'a> {
    pub last_block: bool,
    pub block_number: u16,
    pub raw_data: &'a [u8],
}

impl<'a> ReadDataBlockAccess<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = put_presence(buf, self.last_block)?;
        written += buf.write(&self.block_number.to_be_bytes())?;
        written += crate::axdr::put_octet_string(buf, self.raw_data)?;
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(ReadDataBlockAccess {
            last_block: get_presence(buf)?,
            block_number: get_u16(buf)?,
            raw_data: crate::axdr::get_octet_string(buf)?,
        })
    }
}

/// `Write-Data-Block-Access ::= SEQUENCE { last-block, block-number }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteDataBlockAccess {
    pub last_block: bool,
    pub block_number: u16,
}

impl WriteDataBlockAccess {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = put_presence(buf, self.last_block)?;
        written += buf.write(&self.block_number.to_be_bytes())?;
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(WriteDataBlockAccess {
            last_block: get_presence(buf)?,
            block_number: get_u16(buf)?,
        })
    }
}

/// `Parameterized-Access ::= SEQUENCE { variable-name, selector, parameter }`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ParameterizedAccess<'a> {
    pub variable_name: ObjectName,
    pub selector: u8,
    /// Raw A-XDR bytes of the `parameter` (`Data`) value (zero-copy).
    pub parameter: Reader<'a>,
}

impl<'a> ParameterizedAccess<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = self.variable_name.put(buf)?;
        written += buf.put_u8(self.selector)?;
        written += buf.write(self.parameter.as_bytes())?;
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(ParameterizedAccess {
            variable_name: ObjectName::get(buf)?,
            selector: buf.get_u8()?,
            parameter: data_value(buf)?,
        })
    }
}

/// `Variable-Access-Specification ::= CHOICE`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VariableAccessSpecification<'a> {
    VariableName(ObjectName),                            // [2]
    ParameterizedAccess(ParameterizedAccess<'a>),        // [4]
    BlockNumberAccess(BlockNumberAccess),                // [5]
    ReadDataBlockAccess(ReadDataBlockAccess<'a>),        // [6]
    WriteDataBlockAccess(WriteDataBlockAccess),          // [7]
}

impl<'a> VariableAccessSpecification<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            VariableAccessSpecification::VariableName(v) => {
                let mut w = buf.put_u8(2)?;
                w += v.put(buf)?;
                Ok(w)
            }
            VariableAccessSpecification::ParameterizedAccess(p) => {
                let mut w = buf.put_u8(4)?;
                w += p.put(buf)?;
                Ok(w)
            }
            VariableAccessSpecification::BlockNumberAccess(b) => {
                let mut w = buf.put_u8(5)?;
                w += b.put(buf)?;
                Ok(w)
            }
            VariableAccessSpecification::ReadDataBlockAccess(r) => {
                let mut w = buf.put_u8(6)?;
                w += r.put(buf)?;
                Ok(w)
            }
            VariableAccessSpecification::WriteDataBlockAccess(wr) => {
                let mut w = buf.put_u8(7)?;
                w += wr.put(buf)?;
                Ok(w)
            }
        }
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        match buf.get_u8()? {
            2 => Ok(VariableAccessSpecification::VariableName(ObjectName::get(buf)?)),
            4 => Ok(VariableAccessSpecification::ParameterizedAccess(ParameterizedAccess::get(buf)?)),
            5 => Ok(VariableAccessSpecification::BlockNumberAccess(BlockNumberAccess::get(buf)?)),
            6 => Ok(VariableAccessSpecification::ReadDataBlockAccess(ReadDataBlockAccess::get(buf)?)),
            7 => Ok(VariableAccessSpecification::WriteDataBlockAccess(WriteDataBlockAccess::get(buf)?)),
            t => Err(Error::UnknownChoice { name: "Variable-Access-Specification", choice: t }),
        }
    }
}

/// Lazily-decoded `SEQUENCE OF Variable-Access-Specification` (zero allocation).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VariableAccessSpecificationList<'a> {
    count: usize,
    buf: Reader<'a>,
}

impl<'a> VariableAccessSpecificationList<'a> {
    pub fn read(buf: &mut Reader<'a>) -> Result<Self> {
        let count = get_length(buf)?;
        let start = buf.pos();
        for _ in 0..count {
            VariableAccessSpecification::get(buf)?;
        }
        let end = buf.pos();
        Ok(VariableAccessSpecificationList { count, buf: Reader::new(buf.read_at(start, end - start)?) })
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'a> Iterator for VariableAccessSpecificationList<'a> {
    type Item = Result<VariableAccessSpecification<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(VariableAccessSpecification::get(&mut self.buf))
    }
}


/// One element of `ReadResponse ::= SEQUENCE OF CHOICE`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReadResponseItem<'a> {
    Data(Reader<'a>),               // [0]
    DataAccessError(DataAccessResult), // [1]
    DataBlockResult(DataBlockResult<'a>), // [2]
    BlockNumber(u16),               // [3]
}

impl<'a> ReadResponseItem<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            ReadResponseItem::Data(d) => {
                let mut w = buf.put_u8(0)?;
                w += buf.write(d.as_bytes())?;
                Ok(w)
            }
            ReadResponseItem::DataAccessError(code) => {
                let mut w = buf.put_u8(1)?;
                w += code.put(buf)?;
                Ok(w)
            }
            ReadResponseItem::DataBlockResult(r) => {
                let mut w = buf.put_u8(2)?;
                w += r.put(buf)?;
                Ok(w)
            }
            ReadResponseItem::BlockNumber(n) => {
                let mut w = buf.put_u8(3)?;
                w += buf.write(&n.to_be_bytes())?;
                Ok(w)
            }
        }
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        match buf.get_u8()? {
            0 => Ok(ReadResponseItem::Data(data_value(buf)?)),
            1 => Ok(ReadResponseItem::DataAccessError(DataAccessResult::get(buf)?)),
            2 => Ok(ReadResponseItem::DataBlockResult(DataBlockResult::get(buf)?)),
            3 => Ok(ReadResponseItem::BlockNumber(get_u16(buf)?)),
            t => Err(Error::UnknownChoice { name: "Read-Response", choice: t }),
        }
    }
}

/// Lazily-decoded `ReadResponse ::= SEQUENCE OF CHOICE`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadResponseItemList<'a> {
    count: usize,
    buf: Reader<'a>,
}

impl<'a> ReadResponseItemList<'a> {
    pub fn read(buf: &mut Reader<'a>) -> Result<Self> {
        let count = get_length(buf)?;
        let start = buf.pos();
        for _ in 0..count {
            ReadResponseItem::get(buf)?;
        }
        let end = buf.pos();
        Ok(ReadResponseItemList { count, buf: Reader::new(buf.read_at(start, end - start)?) })
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'a> Iterator for ReadResponseItemList<'a> {
    type Item = Result<ReadResponseItem<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(ReadResponseItem::get(&mut self.buf))
    }
}

/// One element of `WriteResponse ::= SEQUENCE OF CHOICE`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WriteResponseItem {
    Success,          // [0] IMPLICIT NULL
    DataAccessError(DataAccessResult), // [1]
    BlockNumber(u16), // [2]
}

impl WriteResponseItem {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            WriteResponseItem::Success => Ok(buf.put_u8(0)?),
            WriteResponseItem::DataAccessError(code) => {
                let mut w = buf.put_u8(1)?;
                w += code.put(buf)?;
                Ok(w)
            }
            WriteResponseItem::BlockNumber(n) => {
                let mut w = buf.put_u8(2)?;
                w += buf.write(&n.to_be_bytes())?;
                Ok(w)
            }
        }
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        match buf.get_u8()? {
            0 => Ok(WriteResponseItem::Success),
            1 => Ok(WriteResponseItem::DataAccessError(DataAccessResult::get(buf)?)),
            2 => Ok(WriteResponseItem::BlockNumber(get_u16(buf)?)),
            t => Err(Error::UnknownChoice { name: "Write-Response", choice: t }),
        }
    }
}

/// Lazily-decoded `WriteResponse ::= SEQUENCE OF CHOICE`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WriteResponseItemList<'a> {
    count: usize,
    buf: Reader<'a>,
}

impl<'a> WriteResponseItemList<'a> {
    pub fn read(buf: &mut Reader<'a>) -> Result<Self> {
        let count = get_length(buf)?;
        let start = buf.pos();
        for _ in 0..count {
            WriteResponseItem::get(buf)?;
        }
        let end = buf.pos();
        Ok(WriteResponseItemList { count, buf: Reader::new(buf.read_at(start, end - start)?) })
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'a> Iterator for WriteResponseItemList<'a> {
    type Item = Result<WriteResponseItem>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(WriteResponseItem::get(&mut self.buf))
    }
}


/// Генерирует `IMPLICIT ENUMERATED` (1-байтовый код без тега) с `put`/`get`.
macro_rules! enumerated {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $code:expr),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        pub enum $name {
            $($variant = $code),+
        }

        impl $name {
            pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<u8> {
                buf.put_u8(*self as u8)?;
                Ok(1)
            }

            pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
                Ok(match buf.get_u8()? {
                    $($code => Self::$variant,)+
                    _ => return Err(Error::Message(concat!("unknown ", stringify!($name)))),
                })
            }
        }
    };
}

enumerated! {
    /// `application-reference [0] IMPLICIT ENUMERATED`.
    ApplicationReference {
        Other = 0,
        TimeElapsed = 1,
        ApplicationUnreachable = 2,
        ApplicationReferenceInvalid = 3,
        ApplicationContextUnsupported = 4,
        ProviderCommunicationError = 5,
        DecipheringError = 6,
    }
}

enumerated! {
    /// `hardware-resource [1] IMPLICIT ENUMERATED`.
    HardwareResource {
        Other = 0,
        MemoryUnavailable = 1,
        ProcessorResourceUnavailable = 2,
        MassStorageUnavailable = 3,
        OtherResourceUnavailable = 4,
    }
}

enumerated! {
    /// `vde-state-error [2] IMPLICIT ENUMERATED`.
    VdeStateError {
        Other = 0,
        NoDlmsContext = 1,
        LoadingDataSet = 2,
        StatusNochange = 3,
        StatusInoperable = 4,
    }
}

enumerated! {
    /// `service [3] IMPLICIT ENUMERATED`.
    Service {
        Other = 0,
        PduSize = 1,
        ServiceUnsupported = 2,
    }
}

enumerated! {
    /// `definition [4] IMPLICIT ENUMERATED`.
    Definition {
        Other = 0,
        ObjectUndefined = 1,
        ObjectClassInconsistent = 2,
        ObjectAttributeInconsistent = 3,
    }
}

enumerated! {
    /// `access [5] IMPLICIT ENUMERATED`.
    Access {
        Other = 0,
        ScopeOfAccessViolated = 1,
        ObjectAccessViolated = 2,
        HardwareFault = 3,
        ObjectUnavailable = 4,
    }
}

enumerated! {
    /// `initiate [6] IMPLICIT ENUMERATED`.
    Initiate {
        Other = 0,
        DlmsVersionTooLow = 1,
        IncompatibleConformance = 2,
        PduSizeTooShort = 3,
        RefusedByTheVdeHandler = 4,
    }
}

enumerated! {
    /// `load-data-set [7] IMPLICIT ENUMERATED`.
    LoadDataSet {
        Other = 0,
        PrimitiveOutOfSequence = 1,
        NotLoadable = 2,
        DatasetSizeTooLarge = 3,
        NotAwaitedSegment = 4,
        InterpretationFailure = 5,
        StorageFailure = 6,
        DataSetNotReady = 7,
    }
}

enumerated! {
    /// `task [9] IMPLICIT ENUMERATED`.
    Task {
        Other = 0,
        NoRemoteControl = 1,
        TiStopped = 2,
        TiRunning = 3,
        TiUnusable = 4,
    }
}

/// `ServiceError ::= CHOICE` of `IMPLICIT ENUMERATED` alternatives.
///
/// Each variant carries the `IMPLICIT ENUMERATED` code of the corresponding
/// CHOICE alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    /// application-reference [0].
    ApplicationReference(ApplicationReference),
    /// hardware-resource [1].
    HardwareResource(HardwareResource),
    /// vde-state-error [2].
    VdeStateError(VdeStateError),
    /// service [3].
    Service(Service),
    /// definition [4].
    Definition(Definition),
    /// access [5].
    Access(Access),
    /// initiate [6].
    Initiate(Initiate),
    /// load-data-set [7].
    LoadDataSet(LoadDataSet),
    /// task [9].
    Task(Task),
}

impl ServiceError {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let (tag, value) = match *self {
            ServiceError::ApplicationReference(v) => (0, v as u8),
            ServiceError::HardwareResource(v) => (1, v as u8),
            ServiceError::VdeStateError(v) => (2, v as u8),
            ServiceError::Service(v) => (3, v as u8),
            ServiceError::Definition(v) => (4, v as u8),
            ServiceError::Access(v) => (5, v as u8),
            ServiceError::Initiate(v) => (6, v as u8),
            ServiceError::LoadDataSet(v) => (7, v as u8),
            ServiceError::Task(v) => (9, v as u8),
        };
        let mut w = buf.put_u8(tag)?;
        w += buf.put_u8(value)?;
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(match buf.get_u8()? {
            0 => ServiceError::ApplicationReference(ApplicationReference::get(buf)?),
            1 => ServiceError::HardwareResource(HardwareResource::get(buf)?),
            2 => ServiceError::VdeStateError(VdeStateError::get(buf)?),
            3 => ServiceError::Service(Service::get(buf)?),
            4 => ServiceError::Definition(Definition::get(buf)?),
            5 => ServiceError::Access(Access::get(buf)?),
            6 => ServiceError::Initiate(Initiate::get(buf)?),
            7 => ServiceError::LoadDataSet(LoadDataSet::get(buf)?),
            9 => ServiceError::Task(Task::get(buf)?),
            t => return Err(Error::UnknownChoice { name: "Service-Error", choice: t }),
        })
    }
}

/// `ConfirmedServiceError ::= CHOICE { initiateError [1] ServiceError, ... }`.
///
/// `tag` is the service that failed (`1`..`19`); `service_error` is the
/// corresponding [`ServiceError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedServiceError {
    pub tag: u8,
    pub service_error: ServiceError,
}

/// CHOICE tags for [`ConfirmedServiceError`].
pub mod confirmed_service_error_tag {
    pub const INITIATE_ERROR: u8 = 1;
    pub const GET_STATUS: u8 = 2;
    pub const GET_NAME_LIST: u8 = 3;
    pub const GET_VARIABLE_ATTRIBUTE: u8 = 4;
    pub const READ: u8 = 5;
    pub const WRITE: u8 = 6;
    pub const GET_DATA_SET_ATTRIBUTE: u8 = 7;
    pub const GET_TI_ATTRIBUTE: u8 = 8;
    pub const CHANGE_SCOPE: u8 = 9;
    pub const START: u8 = 10;
    pub const STOP: u8 = 11;
    pub const RESUME: u8 = 12;
    pub const MAKE_USABLE: u8 = 13;
    pub const INITIATE_LOAD: u8 = 14;
    pub const LOAD_SEGMENT: u8 = 15;
    pub const TERMINATE_LOAD: u8 = 16;
    pub const INITIATE_UPLOAD: u8 = 17;
    pub const UPLOAD_SEGMENT: u8 = 18;
    pub const TERMINATE_UPLOAD: u8 = 19;
}

impl ConfirmedServiceError {
    pub const TAG: u8 = 14;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += buf.put_u8(self.tag)?;
        w += self.service_error.put(buf)?;
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Confirmed-Service-Error [14]", actual: tag });
        }
        Ok(ConfirmedServiceError {
            tag: buf.get_u8()?,
            service_error: ServiceError::get(buf)?,
        })
    }
}


/// `InitiateRequest ::= SEQUENCE` (`[1] IMPLICIT` in the xDLMS-APDU CHOICE).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InitiateRequest<'a> {
    pub dedicated_key: Option<&'a [u8]>,
    pub response_allowed: bool,
    pub proposed_quality_of_service: Option<i8>,
    pub proposed_dlms_version_number: u8,
    pub proposed_conformance: Conformance,
    pub client_max_receive_pdu_size: u16,
}

impl<'a> InitiateRequest<'a> {
    pub const TAG: u8 = 1;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_presence(buf, self.dedicated_key.is_some())?;
        if let Some(k) = self.dedicated_key {
            w += crate::axdr::put_octet_string(buf, k)?;
        }
        if self.response_allowed {
            w += buf.put_u8(0x00)?;
        } else {
            w += buf.put_u8(0xFF)?;
            w += buf.put_u8(0x00)?;
        }
        w += put_presence(buf, self.proposed_quality_of_service.is_some())?;
        if let Some(q) = self.proposed_quality_of_service {
            w += buf.write(&q.to_be_bytes())?;
        }
        w += buf.put_u8(self.proposed_dlms_version_number)?;
        w += self.proposed_conformance.put(buf)?;
        w += buf.write(&self.client_max_receive_pdu_size.to_be_bytes())?;
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Initiate-Request [1]", actual: tag });
        }
        let dedicated_key = if get_presence(buf)? {
            Some(crate::axdr::get_octet_string(buf)?)
        } else {
            None
        };
        let response_allowed = if get_presence(buf)? {
            buf.get_u8()? != 0
        } else {
            true
        };
        let proposed_quality_of_service = if get_presence(buf)? {
            Some(i8::from_be_bytes([buf.get_u8()?]))
        } else {
            None
        };
        Ok(InitiateRequest {
            dedicated_key,
            response_allowed,
            proposed_quality_of_service,
            proposed_dlms_version_number: buf.get_u8()?,
            proposed_conformance: Conformance::get(buf)?,
            client_max_receive_pdu_size: get_u16(buf)?,
        })
    }
}

/// `InitiateResponse ::= SEQUENCE` (`[8] IMPLICIT` in the xDLMS-APDU CHOICE).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InitiateResponse {
    pub negotiated_quality_of_service: Option<i8>,
    pub negotiated_dlms_version_number: u8,
    pub negotiated_conformance: Conformance,
    pub server_max_receive_pdu_size: u16,
    pub vaa_name: ObjectName,
}

impl InitiateResponse {
    pub const TAG: u8 = 8;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_presence(buf, self.negotiated_quality_of_service.is_some())?;
        if let Some(q) = self.negotiated_quality_of_service {
            w += buf.write(&q.to_be_bytes())?;
        }
        w += buf.put_u8(self.negotiated_dlms_version_number)?;
        w += self.negotiated_conformance.put(buf)?;
        w += buf.write(&self.server_max_receive_pdu_size.to_be_bytes())?;
        w += self.vaa_name.put(buf)?;
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Initiate-Response [8]", actual: tag });
        }
        let negotiated_quality_of_service = if get_presence(buf)? {
            Some(i8::from_be_bytes([buf.get_u8()?]))
        } else {
            None
        };
        Ok(InitiateResponse {
            negotiated_quality_of_service,
            negotiated_dlms_version_number: buf.get_u8()?,
            negotiated_conformance: Conformance::get(buf)?,
            server_max_receive_pdu_size: get_u16(buf)?,
            vaa_name: ObjectName::get(buf)?,
        })
    }
}


/// `ReadRequest ::= SEQUENCE OF Variable-Access-Specification` (`[5] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadRequest<'a> {
    pub variable_access_specifications: VariableAccessSpecificationList<'a>,
}

impl<'a> ReadRequest<'a> {
    pub const TAG: u8 = 5;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_length(buf, self.variable_access_specifications.len())?;
        for item in self.variable_access_specifications {
            w += item?.put(buf)?;
        }
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Read-Request [5]", actual: tag });
        }
        Ok(ReadRequest { variable_access_specifications: VariableAccessSpecificationList::read(buf)? })
    }
}

/// `ReadResponse ::= SEQUENCE OF CHOICE` (`[12] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadResponse<'a> {
    pub results: ReadResponseItemList<'a>,
}

impl<'a> ReadResponse<'a> {
    pub const TAG: u8 = 12;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_length(buf, self.results.len())?;
        for item in self.results {
            w += item?.put(buf)?;
        }
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Read-Response [12]", actual: tag });
        }
        Ok(ReadResponse { results: ReadResponseItemList::read(buf)? })
    }
}

/// `WriteRequest ::= SEQUENCE` (`[6] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WriteRequest<'a> {
    pub variable_access_specifications: VariableAccessSpecificationList<'a>,
    pub list_of_data: ReaderList<'a>,
}

impl<'a> WriteRequest<'a> {
    pub const TAG: u8 = 6;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_length(buf, self.variable_access_specifications.len())?;
        for item in self.variable_access_specifications {
            w += item?.put(buf)?;
        }
        w += put_length(buf, self.list_of_data.len())?;
        for item in self.list_of_data {
            w += buf.write(item?.as_bytes())?;
        }
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Write-Request [6]", actual: tag });
        }
        Ok(WriteRequest {
            variable_access_specifications: VariableAccessSpecificationList::read(buf)?,
            list_of_data: ReaderList::read(buf)?,
        })
    }
}

/// `WriteResponse ::= SEQUENCE OF CHOICE` (`[13] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WriteResponse<'a> {
    pub results: WriteResponseItemList<'a>,
}

impl<'a> WriteResponse<'a> {
    pub const TAG: u8 = 13;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_length(buf, self.results.len())?;
        for item in self.results {
            w += item?.put(buf)?;
        }
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Write-Response [13]", actual: tag });
        }
        Ok(WriteResponse { results: WriteResponseItemList::read(buf)? })
    }
}



/// `Long-Invoke-Id-And-Priority ::= Unsigned32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongInvokeIdAndPriority(pub u32);

impl LongInvokeIdAndPriority {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        Ok(buf.write(&self.0.to_be_bytes())?)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(LongInvokeIdAndPriority(u32::from_be_bytes([
            buf.get_u8()?,
            buf.get_u8()?,
            buf.get_u8()?,
            buf.get_u8()?,
        ])))
    }
}

/// `Notification-Body ::= SEQUENCE { data-value Data }`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NotificationBody<'a> {
    pub data_value: Reader<'a>,
}

impl<'a> NotificationBody<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        Ok(buf.write(self.data_value.as_bytes())?)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(NotificationBody { data_value: data_value(buf)? })
    }
}

/// `Data-Notification ::= SEQUENCE` (`[15] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DataNotification<'a> {
    pub long_invoke_id_and_priority: LongInvokeIdAndPriority,
    pub date_time: &'a [u8],
    pub notification_body: NotificationBody<'a>,
}

impl<'a> DataNotification<'a> {
    pub const TAG: u8 = 15;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += self.long_invoke_id_and_priority.put(buf)?;
        w += crate::axdr::put_octet_string(buf, self.date_time)?;
        w += self.notification_body.put(buf)?;
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Data-Notification [15]", actual: tag });
        }
        Ok(DataNotification {
            long_invoke_id_and_priority: LongInvokeIdAndPriority::get(buf)?,
            date_time: crate::axdr::get_octet_string(buf)?,
            notification_body: NotificationBody::get(buf)?,
        })
    }
}

/// `Data-Notification-Confirm ::= SEQUENCE` (`[16] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DataNotificationConfirm<'a> {
    pub long_invoke_id_and_priority: LongInvokeIdAndPriority,
    pub date_time: &'a [u8],
}

impl<'a> DataNotificationConfirm<'a> {
    pub const TAG: u8 = 16;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += self.long_invoke_id_and_priority.put(buf)?;
        w += crate::axdr::put_octet_string(buf, self.date_time)?;
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Data-Notification-Confirm [16]", actual: tag });
        }
        Ok(DataNotificationConfirm {
            long_invoke_id_and_priority: LongInvokeIdAndPriority::get(buf)?,
            date_time: crate::axdr::get_octet_string(buf)?,
        })
    }
}

/// `UnconfirmedWriteRequest ::= SEQUENCE` (`[22] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnconfirmedWriteRequest<'a> {
    pub variable_access_specifications: VariableAccessSpecificationList<'a>,
    pub list_of_data: ReaderList<'a>,
}

impl<'a> UnconfirmedWriteRequest<'a> {
    pub const TAG: u8 = 22;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_length(buf, self.variable_access_specifications.len())?;
        for item in self.variable_access_specifications {
            w += item?.put(buf)?;
        }
        w += put_length(buf, self.list_of_data.len())?;
        for item in self.list_of_data {
            w += buf.write(item?.as_bytes())?;
        }
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Unconfirmed-Write-Request [22]", actual: tag });
        }
        Ok(UnconfirmedWriteRequest {
            variable_access_specifications: VariableAccessSpecificationList::read(buf)?,
            list_of_data: ReaderList::read(buf)?,
        })
    }
}

/// `InformationReportRequest ::= SEQUENCE` (`[24] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InformationReportRequest<'a> {
    pub current_time: Option<&'a [u8]>,
    pub variable_access_specifications: VariableAccessSpecificationList<'a>,
    pub list_of_data: ReaderList<'a>,
}

impl<'a> InformationReportRequest<'a> {
    pub const TAG: u8 = 24;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_presence(buf, self.current_time.is_some())?;
        if let Some(t) = self.current_time {
            w += crate::axdr::put_octet_string(buf, t)?;
        }
        w += put_length(buf, self.variable_access_specifications.len())?;
        for item in self.variable_access_specifications {
            w += item?.put(buf)?;
        }
        w += put_length(buf, self.list_of_data.len())?;
        for item in self.list_of_data {
            w += buf.write(item?.as_bytes())?;
        }
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Information-Report-Request [24]", actual: tag });
        }
        let current_time = if get_presence(buf)? {
            Some(crate::axdr::get_octet_string(buf)?)
        } else {
            None
        };
        Ok(InformationReportRequest {
            current_time,
            variable_access_specifications: VariableAccessSpecificationList::read(buf)?,
            list_of_data: ReaderList::read(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc<F: FnOnce(&mut ByteBuffer<'_>) -> Result<usize>>(f: F) -> Vec<u8> {
        let mut backing = [0u8; 256];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            f(&mut b).unwrap()
        };
        backing[..n].to_vec()
    }

    #[test]
    fn initiate_request_matches_green_book_example() {
        let req = InitiateRequest {
            dedicated_key: None,
            response_allowed: true,
            proposed_quality_of_service: None,
            proposed_dlms_version_number: 6,
            proposed_conformance: Conformance([0x1C, 0x03, 0x20]),
            client_max_receive_pdu_size: 1200,
        };
        let bytes = enc(|b| req.put(b));
        // Green Book Table 116 (SN referencing): 01 00 00 00 06 5F 1F 04 00 1C 03 20 04 B0
        assert_eq!(
            bytes,
            [0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x1C, 0x03, 0x20, 0x04, 0xB0]
        );

        let mut r = Reader::new(&bytes);
        let decoded = InitiateRequest::get(&mut r).unwrap();
        assert_eq!(decoded.proposed_dlms_version_number, 6);
        assert_eq!(decoded.proposed_conformance, Conformance([0x1C, 0x03, 0x20]));
        assert_eq!(decoded.client_max_receive_pdu_size, 1200);
        assert!(decoded.response_allowed);
        assert!(decoded.dedicated_key.is_none());
    }

    #[test]
    fn initiate_response_matches_green_book_example() {
        let resp = InitiateResponse {
            negotiated_quality_of_service: None,
            negotiated_dlms_version_number: 6,
            negotiated_conformance: Conformance([0x1C, 0x03, 0x20]),
            server_max_receive_pdu_size: 500,
            vaa_name: ObjectName(0xFA00),
        };
        let bytes = enc(|b| resp.put(b));
        // Green Book Table 117 (SN referencing): 08 00 06 5F 1F 04 00 1C 03 20 01 F4 FA 00
        assert_eq!(
            bytes,
            [0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x1C, 0x03, 0x20, 0x01, 0xF4, 0xFA, 0x00]
        );

        let mut r = Reader::new(&bytes);
        let decoded = InitiateResponse::get(&mut r).unwrap();
        assert_eq!(decoded.vaa_name, ObjectName(0xFA00));
        assert_eq!(decoded.server_max_receive_pdu_size, 500);
    }

    #[test]
    fn confirmed_service_error_matches_green_book_example() {
        let err = ConfirmedServiceError {
            tag: confirmed_service_error_tag::INITIATE_ERROR,
            service_error: ServiceError::Initiate(Initiate::DlmsVersionTooLow),
        };
        let bytes = enc(|b| err.put(b));
        // Green Book: 0E 01 06 01
        assert_eq!(bytes, [0x0E, 0x01, 0x06, 0x01]);

        let mut r = Reader::new(&bytes);
        assert_eq!(ConfirmedServiceError::get(&mut r).unwrap(), err);
    }

    #[test]
    fn read_request_and_response_roundtrip() {
        // ReadRequest: [5], length=1, variable-name [2] ObjectName(0xFA00)
        let req_bytes = [0x05, 0x01, 0x02, 0xFA, 0x00];
        let mut r = Reader::new(&req_bytes);
        let req = ReadRequest::get(&mut r).unwrap();
        assert_eq!(req.variable_access_specifications.len(), 1);
        let mut list = req.variable_access_specifications;
        assert_eq!(
            list.next().unwrap().unwrap(),
            VariableAccessSpecification::VariableName(ObjectName(0xFA00))
        );
        assert_eq!(enc(|b| req.put(b)), req_bytes);

        // ReadResponse: [12], length=2, data[0] Unsigned(1), data-access-error[1](3)
        let resp_bytes = [0x0C, 0x02, 0x00, 0x11, 0x01, 0x01, 0x03];
        let mut r = Reader::new(&resp_bytes);
        let resp = ReadResponse::get(&mut r).unwrap();
        assert_eq!(resp.results.len(), 2);
        let mut it = resp.results;
        assert_eq!(it.next().unwrap().unwrap(), ReadResponseItem::Data(Reader::new(&[0x11, 0x01])));
        assert_eq!(it.next().unwrap().unwrap(), ReadResponseItem::DataAccessError(DataAccessResult::ReadWriteDenied));
        assert_eq!(enc(|b| resp.put(b)), resp_bytes);
    }
}

