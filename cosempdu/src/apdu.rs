//! xDLMS APDU types with A-XDR encoding (IEC 61334-6).
//!
//! Mirrors the confirmed GET/SET/ACTION request-response services from
//! `src/COSEMpdu/apdu.py` (Green Book 8.3). The complete xDLMS APDU is a large
//! CHOICE; this module implements the most commonly used services plus the
//! [`XDLMSApdu`] dispatch type.

use crate::axdr::{get_length, put_length};
use bytebuffer::{ByteBuffer, Reader};
use crate::data::{data_value, Codec};
use crate::error::{Error, Result};

/// Invoke-Id-And-Priority ::= Unsigned8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvokeIdAndPriority(pub u8);

impl InvokeIdAndPriority {
    pub fn from_bits(invoke_id: u8, confirmed: bool, high_priority: bool) -> Self {
        InvokeIdAndPriority(
            ((invoke_id & 0x0F) << 4) | ((confirmed as u8) << 1) | (high_priority as u8),
        )
    }

    pub fn invoke_id(&self) -> u8 {
        self.0 >> 4
    }

    pub fn is_confirmed(&self) -> bool {
        (self.0 >> 1) & 1 != 0
    }

    pub fn is_high_priority(&self) -> bool {
        self.0 & 1 != 0
    }

    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        Ok(buf.put_u8(self.0)?)
    }

    fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(InvokeIdAndPriority(buf.get_u8()?))
    }
}

/// Cosem-Attribute-Descriptor ::= SEQUENCE { class-id, instance-id, attribute-id }.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CosemAttributeDescriptor {
    pub class_id: u16,
    pub instance_id: [u8; 6],
    pub attribute_id: i8,
}

impl CosemAttributeDescriptor {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.write(&self.class_id.to_be_bytes())?;
        written += buf.write(&self.instance_id)?;
        written += buf.write(&self.attribute_id.to_be_bytes())?;
        Ok(written)
    }

    fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(CosemAttributeDescriptor {
            class_id: u16::from_be_bytes(read_n::<2>(buf)?),
            instance_id: read_n::<6>(buf)?,
            attribute_id: i8::from_be_bytes(read_n::<1>(buf)?),
        })
    }
}

/// Cosem-Method-Descriptor ::= SEQUENCE { class-id, instance-id, method-id }.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CosemMethodDescriptor {
    pub class_id: u16,
    pub instance_id: [u8; 6],
    pub method_id: i8,
}

impl CosemMethodDescriptor {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.write(&self.class_id.to_be_bytes())?;
        written += buf.write(&self.instance_id)?;
        written += buf.write(&self.method_id.to_be_bytes())?;
        Ok(written)
    }

    fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(CosemMethodDescriptor {
            class_id: u16::from_be_bytes(read_n::<2>(buf)?),
            instance_id: read_n::<6>(buf)?,
            method_id: i8::from_be_bytes(read_n::<1>(buf)?),
        })
    }
}

/// Selective-Access-Descriptor ::= SEQUENCE { access-selector, access-parameters }.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelectiveAccessDescriptor<'a> {
    pub access_selector: u8,
    /// Raw A-XDR bytes of the `access-parameters` value (zero-copy).
    pub access_parameters: Reader<'a>,
}

impl<'a> SelectiveAccessDescriptor<'a> {
    /// Encode a selective-access descriptor from *typed* values (asymmetric
    /// write side): `access_parameters` is a [`Codec`], not pre-encoded bytes.
    pub fn put(
        access_selector: u8,
        access_parameters: &dyn Codec,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(access_selector)?;
        written += access_parameters.put(buf)?;
        Ok(written)
    }

    fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let access_selector = buf.get_u8()?;
        let access_parameters = data_value(buf)?;
        Ok(SelectiveAccessDescriptor {
            access_selector,
            access_parameters,
        })
    }
}

/// Write-side view of a [`SelectiveAccessDescriptor`] for encoding.
#[derive(Clone, Copy)]
pub struct SelectiveAccessDescriptorWrite<'a> {
    pub access_selector: u8,
    pub access_parameters: &'a dyn Codec,
}

impl SelectiveAccessDescriptorWrite<'_> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        SelectiveAccessDescriptor::put(self.access_selector, self.access_parameters, buf)
    }
}

fn read_n<const N: usize>(buf: &mut Reader<'_>) -> Result<[u8; N]> {
    let mut arr = [0u8; N];
    arr.copy_from_slice(buf.read(N)?);
    Ok(arr)
}

/// Write an OPTIONAL presence flag (A-XDR §6.8): 0x00 absent, 0xFF present.
fn put_presence(buf: &mut ByteBuffer<'_>, present: bool) -> Result<usize> {
    Ok(buf.put_u8(if present { 0xFF } else { 0x00 })?)
}

fn get_presence(buf: &mut Reader<'_>) -> Result<bool> {
    Ok(buf.get_u8()? != 0)
}

/// Lazily-decoded list of attribute descriptors (zero allocation: elements are
/// read from the input buffer on demand).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DescriptorList<'a> {
    count: usize,
    buf: Reader<'a>,
}

impl<'a> DescriptorList<'a> {
    /// Read a descriptor list from `buf` (advancing it), returning a lazy cursor.
    pub fn read(buf: &mut Reader<'a>) -> Result<Self> {
        let count = get_length(buf)?;
        let start = buf.pos();
        for _ in 0..count {
            Self::decode_one(buf)?;
        }
        let end = buf.pos();
        Ok(DescriptorList { count, buf: Reader::new(buf.read_at(start, end - start)?) })
    }

    fn decode_one(
        buf: &mut Reader<'a>,
    ) -> Result<(CosemAttributeDescriptor, Option<SelectiveAccessDescriptor<'a>>)> {
        let descriptor = CosemAttributeDescriptor::get(buf)?;
        let sel = if get_presence(buf)? {
            Some(SelectiveAccessDescriptor::get(buf)?)
        } else {
            None
        };
        Ok((descriptor, sel))
    }

    /// Number of elements remaining in the list.
    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'a> Iterator for DescriptorList<'a> {
    type Item = Result<(CosemAttributeDescriptor, Option<SelectiveAccessDescriptor<'a>>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(Self::decode_one(&mut self.buf))
    }
}

/// Lazily-decoded list of `CosemMethodDescriptor` (zero allocation).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MethodDescriptorList<'a> {
    count: usize,
    buf: Reader<'a>,
}

impl<'a> MethodDescriptorList<'a> {
    /// Read a method-descriptor list from `buf`, returning a lazy cursor.
    pub fn read(buf: &mut Reader<'a>) -> Result<Self> {
        let count = get_length(buf)?;
        let start = buf.pos();
        for _ in 0..count {
            CosemMethodDescriptor::get(buf)?;
        }
        let end = buf.pos();
        Ok(MethodDescriptorList { count, buf: Reader::new(buf.read_at(start, end - start)?) })
    }

    /// Number of elements remaining in the list.
    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'a> Iterator for MethodDescriptorList<'a> {
    type Item = Result<CosemMethodDescriptor>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(CosemMethodDescriptor::get(&mut self.buf))
    }
}

/// Lazily-decoded list of A-XDR values (zero allocation).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReaderList<'a> {
    count: usize,
    buf: Reader<'a>,
}

impl<'a> ReaderList<'a> {
    /// Read a value list from `buf` (advancing it), returning a lazy cursor.
    pub fn read(buf: &mut Reader<'a>) -> Result<Self> {
        let count = get_length(buf)?;
        let start = buf.pos();
        for _ in 0..count {
            data_value(buf)?;
        }
        let end = buf.pos();
        Ok(ReaderList { count, buf: Reader::new(buf.read_at(start, end - start)?) })
    }

    /// Number of elements remaining in the list.
    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'a> Iterator for ReaderList<'a> {
    type Item = Result<Reader<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(data_value(&mut self.buf))
    }
}

/// Lazily-decoded list of `Get-Data-Result` (zero allocation).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetDataResultList<'a> {
    count: usize,
    buf: Reader<'a>,
}

impl<'a> GetDataResultList<'a> {
    /// Read a `Get-Data-Result` list from `buf`, returning a lazy cursor.
    pub fn read(buf: &mut Reader<'a>) -> Result<Self> {
        let count = get_length(buf)?;
        let start = buf.pos();
        for _ in 0..count {
            GetDataResult::get(buf)?;
        }
        let end = buf.pos();
        Ok(GetDataResultList { count, buf: Reader::new(buf.read_at(start, end - start)?) })
    }

    /// Number of elements remaining in the list.
    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'a> Iterator for GetDataResultList<'a> {
    type Item = Result<GetDataResult<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(GetDataResult::get(&mut self.buf))
    }
}

/// Lazily-decoded list of `ActionResponseWithOptionalData` (zero allocation).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ActionResponseWithOptionalDataList<'a> {
    count: usize,
    buf: Reader<'a>,
}

impl<'a> ActionResponseWithOptionalDataList<'a> {
    /// Read an action-response list from `buf`, returning a lazy cursor.
    pub fn read(buf: &mut Reader<'a>) -> Result<Self> {
        let count = get_length(buf)?;
        let start = buf.pos();
        for _ in 0..count {
            ActionResponseWithOptionalData::get(buf)?;
        }
        let end = buf.pos();
        Ok(ActionResponseWithOptionalDataList {
            count,
            buf: Reader::new(buf.read_at(start, end - start)?),
        })
    }

    /// Number of elements remaining in the list.
    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'a> Iterator for ActionResponseWithOptionalDataList<'a> {
    type Item = Result<ActionResponseWithOptionalData<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(ActionResponseWithOptionalData::get(&mut self.buf))
    }
}

/// Get-Request ::= [192] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum GetRequest<'a> {
    Normal {
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        access_selection: Option<SelectiveAccessDescriptor<'a>>,
    },
    Next {
        invoke: InvokeIdAndPriority,
        block_number: u32,
    },
    WithList {
        invoke: InvokeIdAndPriority,
        descriptors: DescriptorList<'a>,
    },
}

impl<'a> GetRequest<'a> {
    const TAG: u8 = 192;

    /// Encode the `normal` alternative from typed values.
    pub fn put_normal(
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        access_selection: Option<SelectiveAccessDescriptorWrite<'_>>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(1)?;
        written += invoke.put(buf)?;
        written += descriptor.put(buf)?;
        written += put_presence(buf, access_selection.is_some())?;
        if let Some(sel) = access_selection {
            written += sel.put(buf)?;
        }
        Ok(written)
    }

    /// Encode the `next` alternative.
    pub fn put_next(
        invoke: InvokeIdAndPriority,
        block_number: u32,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(2)?;
        written += invoke.put(buf)?;
        written += buf.write(&block_number.to_be_bytes())?;
        Ok(written)
    }

    /// Encode the `with-list` alternative from typed values.
    pub fn put_with_list(
        invoke: InvokeIdAndPriority,
        descriptors: &[(CosemAttributeDescriptor, Option<SelectiveAccessDescriptorWrite<'_>>)],
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(3)?;
        written += invoke.put(buf)?;
        written += put_length(buf, descriptors.len())?;
        for (desc, sel) in descriptors {
            written += desc.put(buf)?;
            written += put_presence(buf, sel.is_some())?;
            if let Some(s) = sel {
                written += s.put(buf)?;
            }
        }
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Get-Request [192]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptor = CosemAttributeDescriptor::get(buf)?;
                let access_selection = if get_presence(buf)? {
                    Some(SelectiveAccessDescriptor::get(buf)?)
                } else {
                    None
                };
                GetRequest::Normal {
                    invoke,
                    descriptor,
                    access_selection,
                }
            }
            2 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
                GetRequest::Next {
                    invoke,
                    block_number,
                }
            }
            3 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptors = DescriptorList::read(buf)?;
                GetRequest::WithList { invoke, descriptors }
            }
            other => return Err(Error::UnknownChoice { name: "Get-Request", choice: other }),
        })
    }
}

/// Data-Access-Result ::= ENUMERATED (single byte, no tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataAccessResult {
    Success = 0,
    HardwareFault = 1,
    TemporaryFailure = 2,
    ReadWriteDenied = 3,
    ObjectUndefined = 4,
    ObjectClassInconsistent = 9,
    ObjectUnavailable = 11,
    TypeUnmatched = 12,
    ScopeOfAccessViolated = 13,
    DataBlockUnavailable = 14,
    LongGetAborted = 15,
    NoLongGetInProgress = 16,
    LongSetAborted = 17,
    NoLongSetInProgress = 18,
    DataBlockNumberInvalid = 19,
    OtherReason = 250,
}

impl DataAccessResult {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        Ok(buf.put_u8(*self as u8)?)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(match buf.get_u8()? {
            0 => Self::Success,
            1 => Self::HardwareFault,
            2 => Self::TemporaryFailure,
            3 => Self::ReadWriteDenied,
            4 => Self::ObjectUndefined,
            9 => Self::ObjectClassInconsistent,
            11 => Self::ObjectUnavailable,
            12 => Self::TypeUnmatched,
            13 => Self::ScopeOfAccessViolated,
            14 => Self::DataBlockUnavailable,
            15 => Self::LongGetAborted,
            16 => Self::NoLongGetInProgress,
            17 => Self::LongSetAborted,
            18 => Self::NoLongSetInProgress,
            19 => Self::DataBlockNumberInvalid,
            250 => Self::OtherReason,
            _ => return Err(Error::Message("unknown data-access-result")),
        })
    }
}

/// Get-Data-Result ::= CHOICE { data [0], data-access-error [1] }.
///
/// # Read/write asymmetry — when is a `put_data` helper necessary?
///
/// `get` returns `Data(Reader)`, the raw value bytes (zero-copy). Encoding is
/// *asymmetric*: instead of a `put(&self)` that would re-emit those bytes, use
/// [`GetDataResult::put_data`] / [`GetDataResult::put_access_error`] with the
/// *typed* value. That avoids a pre-encode round-trip (`encode → scratch →
/// Reader`) on the write side.
///
/// Rule of thumb to check whether a field needs the asymmetric helper: if the
/// field carries a semantic *value* (a [`Codec`]), use a `put_*` helper taking
/// `&dyn Codec`; if it carries *already-encoded bytes* (e.g. a datablock's
/// `raw-data: &[u8]`), a plain byte field with a symmetric `put` is fine.
/// Concretely, every field of type `Data` needs the helper — grep for `Data<'`
/// in the message definitions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GetDataResult<'a> {
    /// Raw A-XDR bytes of the `data` value (zero-copy).
    Data(Reader<'a>),
    DataAccessError(DataAccessResult),
}

impl<'a> GetDataResult<'a> {
    /// Encode the `data` alternative: CHOICE tag `0` + the typed value.
    pub fn put_data(data: &dyn Codec, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(0)?;
        written += data.put(buf)?;
        Ok(written)
    }

    /// Encode the `data-access-error` alternative: CHOICE tag `1` + error code.
    pub fn put_access_error(code: DataAccessResult, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(1)?;
        written += code.put(buf)?;
        Ok(written)
    }

    fn get(buf: &mut Reader<'a>) -> Result<Self> {
        match buf.get_u8()? {
            0 => Ok(GetDataResult::Data(data_value(buf)?)),
            1 => Ok(GetDataResult::DataAccessError(DataAccessResult::get(buf)?)),
            t => Err(Error::UnknownChoice { name: "Get-Data-Result", choice: t }),
        }
    }
}

/// Write-side view of the `Get-Data-Result` CHOICE for encoding.
#[derive(Clone, Copy)]
pub enum GetDataResultWrite<'a> {
    Data(&'a dyn Codec),
    DataAccessError(DataAccessResult),
}

impl GetDataResultWrite<'_> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match *self {
            GetDataResultWrite::Data(codec) => GetDataResult::put_data(codec, buf),
            GetDataResultWrite::DataAccessError(code) => GetDataResult::put_access_error(code, buf),
        }
    }
}

/// DataBlock-G.result ::= CHOICE { raw-data [0], data-access-result [1] }.
#[derive(Debug, Clone, PartialEq)]
pub enum DataBlockGResult<'a> {
    RawData(&'a [u8]),
    DataAccessError(DataAccessResult),
}

impl<'a> DataBlockGResult<'a> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            DataBlockGResult::RawData(bytes) => {
                let mut written = buf.put_u8(0)?;
                written += crate::axdr::put_octet_string(buf, bytes)?;
                Ok(written)
            }
            DataBlockGResult::DataAccessError(code) => {
                let mut written = buf.put_u8(1)?;
                written += code.put(buf)?;
                Ok(written)
            }
        }
    }

    fn get(buf: &mut Reader<'a>) -> Result<Self> {
        match buf.get_u8()? {
            0 => Ok(DataBlockGResult::RawData(crate::axdr::get_octet_string(buf)?)),
            1 => Ok(DataBlockGResult::DataAccessError(DataAccessResult::get(buf)?)),
            t => Err(Error::UnknownChoice { name: "DataBlock-G.result", choice: t }),
        }
    }
}

/// DataBlock-G ::= SEQUENCE { last-block, block-number, result }.
#[derive(Debug, Clone, PartialEq)]
pub struct DataBlockG<'a> {
    pub last_block: bool,
    pub block_number: u32,
    pub result: DataBlockGResult<'a>,
}

impl<'a> DataBlockG<'a> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = put_presence(buf, self.last_block)?;
        written += buf.write(&self.block_number.to_be_bytes())?;
        written += self.result.put(buf)?;
        Ok(written)
    }

    fn get(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(DataBlockG {
            last_block: get_presence(buf)?,
            block_number: u32::from_be_bytes(read_n::<4>(buf)?),
            result: DataBlockGResult::get(buf)?,
        })
    }
}

/// DataBlock-SA ::= SEQUENCE { last-block, block-number, raw-data }.
#[derive(Debug, Clone, PartialEq)]
pub struct DataBlockSA<'a> {
    pub last_block: bool,
    pub block_number: u32,
    pub raw_data: &'a [u8],
}

impl<'a> DataBlockSA<'a> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = put_presence(buf, self.last_block)?;
        written += buf.write(&self.block_number.to_be_bytes())?;
        written += crate::axdr::put_octet_string(buf, &self.raw_data)?;
        Ok(written)
    }

    fn get(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(DataBlockSA {
            last_block: get_presence(buf)?,
            block_number: u32::from_be_bytes(read_n::<4>(buf)?),
            raw_data: crate::axdr::get_octet_string(buf)?,
        })
    }
}

/// Action-Response-With-Optional-Data ::= SEQUENCE { result, return-parameters OPTIONAL }.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ActionResponseWithOptionalData<'a> {
    pub result: u8,
    pub return_parameters: Option<GetDataResult<'a>>,
}

impl<'a> ActionResponseWithOptionalData<'a> {
    /// Encode from typed values: `return_parameters` is a `Get-Data-Result`
    /// (data or error), written via the asymmetric helper.
    pub fn put(
        result: u8,
        return_parameters: Option<GetDataResultWrite<'_>>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(result)?;
        written += put_presence(buf, return_parameters.is_some())?;
        if let Some(rp) = return_parameters {
            written += rp.put(buf)?;
        }
        Ok(written)
    }

    fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let result = buf.get_u8()?;
        let return_parameters = if get_presence(buf)? {
            Some(GetDataResult::get(buf)?)
        } else {
            None
        };
        Ok(ActionResponseWithOptionalData {
            result,
            return_parameters,
        })
    }
}

/// Write-side view of an [`ActionResponseWithOptionalData`] for encoding.
#[derive(Clone, Copy)]
pub struct ActionResponseWithOptionalDataWrite<'a> {
    pub result: u8,
    pub return_parameters: Option<GetDataResultWrite<'a>>,
}

impl ActionResponseWithOptionalDataWrite<'_> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        ActionResponseWithOptionalData::put(self.result, self.return_parameters, buf)
    }
}

/// Get-Response ::= [196] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum GetResponse<'a> {
    Normal {
        invoke: InvokeIdAndPriority,
        result: GetDataResult<'a>,
    },
    WithDatablock {
        invoke: InvokeIdAndPriority,
        result: DataBlockG<'a>,
    },
    WithList {
        invoke: InvokeIdAndPriority,
        results: GetDataResultList<'a>,
    },
}

impl<'a> GetResponse<'a> {
    const TAG: u8 = 196;

    /// Encode the `normal` alternative from typed values.
    pub fn put_normal(
        invoke: InvokeIdAndPriority,
        result: GetDataResultWrite<'_>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(1)?;
        written += invoke.put(buf)?;
        written += result.put(buf)?;
        Ok(written)
    }

    /// Encode the `with-datablock` alternative.
    pub fn put_with_datablock(
        invoke: InvokeIdAndPriority,
        result: &DataBlockG<'_>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(2)?;
        written += invoke.put(buf)?;
        written += result.put(buf)?;
        Ok(written)
    }

    /// Encode the `with-list` alternative from typed values.
    pub fn put_with_list(
        invoke: InvokeIdAndPriority,
        results: &[GetDataResultWrite<'_>],
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(3)?;
        written += invoke.put(buf)?;
        written += put_length(buf, results.len())?;
        for r in results {
            written += r.put(buf)?;
        }
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Get-Response [196]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let result = GetDataResult::get(buf)?;
                GetResponse::Normal { invoke, result }
            }
            2 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let result = DataBlockG::get(buf)?;
                GetResponse::WithDatablock { invoke, result }
            }
            3 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let results = GetDataResultList::read(buf)?;
                GetResponse::WithList { invoke, results }
            }
            other => return Err(Error::UnknownChoice { name: "Get-Response", choice: other }),
        })
    }
}

/// Set-Request ::= [193] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum SetRequest<'a> {
    Normal {
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        access_selection: Option<SelectiveAccessDescriptor<'a>>,
        value: Reader<'a>,
    },
    WithFirstDatablock {
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        access_selection: Option<SelectiveAccessDescriptor<'a>>,
        datablock: DataBlockSA<'a>,
    },
    WithDatablock {
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        access_selection: Option<SelectiveAccessDescriptor<'a>>,
        datablock: DataBlockSA<'a>,
    },
    WithList {
        invoke: InvokeIdAndPriority,
        descriptors: DescriptorList<'a>,
        values: ReaderList<'a>,
    },
    WithListAndFirstDatablock {
        invoke: InvokeIdAndPriority,
        descriptors: DescriptorList<'a>,
        datablock: DataBlockSA<'a>,
    },
}

impl<'a> SetRequest<'a> {
    const TAG: u8 = 193;

    /// Encode the `normal` alternative from typed values.
    pub fn put_normal(
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        access_selection: Option<SelectiveAccessDescriptorWrite<'_>>,
        value: &dyn Codec,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(1)?;
        written += invoke.put(buf)?;
        written += descriptor.put(buf)?;
        written += put_presence(buf, access_selection.is_some())?;
        if let Some(sel) = access_selection {
            written += sel.put(buf)?;
        }
        written += value.put(buf)?;
        Ok(written)
    }

    /// Encode the `with-first-datablock` alternative.
    pub fn put_with_first_datablock(
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        access_selection: Option<SelectiveAccessDescriptorWrite<'_>>,
        datablock: &DataBlockSA<'_>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(2)?;
        written += invoke.put(buf)?;
        written += descriptor.put(buf)?;
        written += put_presence(buf, access_selection.is_some())?;
        if let Some(sel) = access_selection {
            written += sel.put(buf)?;
        }
        written += datablock.put(buf)?;
        Ok(written)
    }

    /// Encode the `with-datablock` alternative.
    pub fn put_with_datablock(
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        access_selection: Option<SelectiveAccessDescriptorWrite<'_>>,
        datablock: &DataBlockSA<'_>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(3)?;
        written += invoke.put(buf)?;
        written += descriptor.put(buf)?;
        written += put_presence(buf, access_selection.is_some())?;
        if let Some(sel) = access_selection {
            written += sel.put(buf)?;
        }
        written += datablock.put(buf)?;
        Ok(written)
    }

    /// Encode the `with-list` alternative from typed values.
    pub fn put_with_list(
        invoke: InvokeIdAndPriority,
        descriptors: &[(CosemAttributeDescriptor, Option<SelectiveAccessDescriptorWrite<'_>>)],
        values: &[&dyn Codec],
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(4)?;
        written += invoke.put(buf)?;
        written += put_length(buf, descriptors.len())?;
        for (desc, sel) in descriptors {
            written += desc.put(buf)?;
            written += put_presence(buf, sel.is_some())?;
            if let Some(s) = sel {
                written += s.put(buf)?;
            }
        }
        written += put_length(buf, values.len())?;
        for v in values {
            written += v.put(buf)?;
        }
        Ok(written)
    }

    /// Encode the `with-list-and-first-datablock` alternative.
    pub fn put_with_list_and_first_datablock(
        invoke: InvokeIdAndPriority,
        descriptors: &[(CosemAttributeDescriptor, Option<SelectiveAccessDescriptorWrite<'_>>)],
        datablock: &DataBlockSA<'_>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(5)?;
        written += invoke.put(buf)?;
        written += put_length(buf, descriptors.len())?;
        for (desc, sel) in descriptors {
            written += desc.put(buf)?;
            written += put_presence(buf, sel.is_some())?;
            if let Some(s) = sel {
                written += s.put(buf)?;
            }
        }
        written += datablock.put(buf)?;
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Set-Request [193]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptor = CosemAttributeDescriptor::get(buf)?;
                let access_selection = if get_presence(buf)? {
                    Some(SelectiveAccessDescriptor::get(buf)?)
                } else {
                    None
                };
                let value = data_value(buf)?;
                SetRequest::Normal {
                    invoke,
                    descriptor,
                    access_selection,
                    value,
                }
            }
            2 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptor = CosemAttributeDescriptor::get(buf)?;
                let access_selection = if get_presence(buf)? {
                    Some(SelectiveAccessDescriptor::get(buf)?)
                } else {
                    None
                };
                let datablock = DataBlockSA::get(buf)?;
                SetRequest::WithFirstDatablock {
                    invoke,
                    descriptor,
                    access_selection,
                    datablock,
                }
            }
            3 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptor = CosemAttributeDescriptor::get(buf)?;
                let access_selection = if get_presence(buf)? {
                    Some(SelectiveAccessDescriptor::get(buf)?)
                } else {
                    None
                };
                let datablock = DataBlockSA::get(buf)?;
                SetRequest::WithDatablock {
                    invoke,
                    descriptor,
                    access_selection,
                    datablock,
                }
            }
            4 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptors = DescriptorList::read(buf)?;
                let values = ReaderList::read(buf)?;
                SetRequest::WithList {
                    invoke,
                    descriptors,
                    values,
                }
            }
            5 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptors = DescriptorList::read(buf)?;
                let datablock = DataBlockSA::get(buf)?;
                SetRequest::WithListAndFirstDatablock {
                    invoke,
                    descriptors,
                    datablock,
                }
            }
            other => return Err(Error::UnknownChoice { name: "Set-Request", choice: other }),
        })
    }
}

/// Lazily-decoded list of [`DataAccessResult`] (zero allocation).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DataAccessResultList<'a> {
    count: usize,
    buf: Reader<'a>,
}

impl<'a> DataAccessResultList<'a> {
    /// Read a `Data-Access-Result` list from `buf`, returning a lazy cursor.
    pub fn read(buf: &mut Reader<'a>) -> Result<Self> {
        let count = get_length(buf)?;
        let start = buf.pos();
        for _ in 0..count {
            DataAccessResult::get(buf)?;
        }
        let end = buf.pos();
        Ok(DataAccessResultList { count, buf: Reader::new(buf.read_at(start, end - start)?) })
    }

    /// Number of elements remaining in the list.
    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'a> Iterator for DataAccessResultList<'a> {
    type Item = Result<DataAccessResult>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(DataAccessResult::get(&mut self.buf))
    }
}

/// Set-Response ::= [197] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum SetResponse<'a> {
    Normal {
        invoke: InvokeIdAndPriority,
        result: DataAccessResult,
    },
    Datablock {
        invoke: InvokeIdAndPriority,
        block_number: u32,
    },
    LastDatablock {
        invoke: InvokeIdAndPriority,
        result: DataAccessResult,
        block_number: u32,
    },
    LastDatablockWithList {
        invoke: InvokeIdAndPriority,
        block_number: u32,
    },
    WithList {
        invoke: InvokeIdAndPriority,
        results: DataAccessResultList<'a>,
    },
}

impl<'a> SetResponse<'a> {
    const TAG: u8 = 197;

    /// Encode the `normal` alternative.
    pub fn put_normal(
        invoke: InvokeIdAndPriority,
        result: DataAccessResult,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(1)?;
        written += invoke.put(buf)?;
        written += result.put(buf)?;
        Ok(written)
    }

    /// Encode the `datablock` alternative.
    pub fn put_datablock(
        invoke: InvokeIdAndPriority,
        block_number: u32,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(2)?;
        written += invoke.put(buf)?;
        written += buf.write(&block_number.to_be_bytes())?;
        Ok(written)
    }

    /// Encode the `last-datablock` alternative.
    pub fn put_last_datablock(
        invoke: InvokeIdAndPriority,
        result: DataAccessResult,
        block_number: u32,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(3)?;
        written += invoke.put(buf)?;
        written += result.put(buf)?;
        written += buf.write(&block_number.to_be_bytes())?;
        Ok(written)
    }

    /// Encode the `last-datablock-with-list` alternative.
    pub fn put_last_datablock_with_list(
        invoke: InvokeIdAndPriority,
        block_number: u32,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(4)?;
        written += invoke.put(buf)?;
        written += buf.write(&block_number.to_be_bytes())?;
        Ok(written)
    }

    /// Encode the `with-list` alternative.
    pub fn put_with_list(
        invoke: InvokeIdAndPriority,
        results: &[DataAccessResult],
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(5)?;
        written += invoke.put(buf)?;
        written += put_length(buf, results.len())?;
        for r in results {
            written += r.put(buf)?;
        }
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Set-Response [197]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let result = DataAccessResult::get(buf)?;
                SetResponse::Normal { invoke, result }
            }
            2 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
                SetResponse::Datablock { invoke, block_number }
            }
            3 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let result = DataAccessResult::get(buf)?;
                let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
                SetResponse::LastDatablock { invoke, result, block_number }
            }
            4 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
                SetResponse::LastDatablockWithList { invoke, block_number }
            }
            5 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let results = DataAccessResultList::read(buf)?;
                SetResponse::WithList { invoke, results }
            }
            other => return Err(Error::UnknownChoice { name: "Set-Response", choice: other }),
        })
    }
}

/// Action-Request ::= [195] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionRequest<'a> {
    Normal {
        invoke: InvokeIdAndPriority,
        descriptor: CosemMethodDescriptor,
        method_invocation_parameters: Option<Reader<'a>>,
    },
    NextPblock {
        invoke: InvokeIdAndPriority,
        block_number: u32,
    },
    WithList {
        invoke: InvokeIdAndPriority,
        descriptors: MethodDescriptorList<'a>,
        method_invocation_parameters: ReaderList<'a>,
    },
    WithFirstPblock {
        invoke: InvokeIdAndPriority,
        descriptor: CosemMethodDescriptor,
        pblock: DataBlockSA<'a>,
    },
    WithListAndFirstPblock {
        invoke: InvokeIdAndPriority,
        descriptors: MethodDescriptorList<'a>,
        pblock: DataBlockSA<'a>,
    },
    WithPblock {
        invoke: InvokeIdAndPriority,
        pblock: DataBlockSA<'a>,
    },
}

impl<'a> ActionRequest<'a> {
    const TAG: u8 = 195;

    /// Encode the `normal` alternative from typed values.
    pub fn put_normal(
        invoke: InvokeIdAndPriority,
        descriptor: CosemMethodDescriptor,
        method_invocation_parameters: Option<&dyn Codec>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(1)?;
        written += invoke.put(buf)?;
        written += descriptor.put(buf)?;
        written += put_presence(buf, method_invocation_parameters.is_some())?;
        if let Some(d) = method_invocation_parameters {
            written += d.put(buf)?;
        }
        Ok(written)
    }

    /// Encode the `next-pblock` alternative.
    pub fn put_next_pblock(
        invoke: InvokeIdAndPriority,
        block_number: u32,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(2)?;
        written += invoke.put(buf)?;
        written += buf.write(&block_number.to_be_bytes())?;
        Ok(written)
    }

    /// Encode the `with-list` alternative from typed values.
    pub fn put_with_list(
        invoke: InvokeIdAndPriority,
        descriptors: &[CosemMethodDescriptor],
        method_invocation_parameters: &[&dyn Codec],
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(3)?;
        written += invoke.put(buf)?;
        written += put_length(buf, descriptors.len())?;
        for desc in descriptors {
            written += desc.put(buf)?;
        }
        written += put_length(buf, method_invocation_parameters.len())?;
        for d in method_invocation_parameters {
            written += d.put(buf)?;
        }
        Ok(written)
    }

    /// Encode the `with-first-pblock` alternative.
    pub fn put_with_first_pblock(
        invoke: InvokeIdAndPriority,
        descriptor: CosemMethodDescriptor,
        pblock: &DataBlockSA<'_>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(4)?;
        written += invoke.put(buf)?;
        written += descriptor.put(buf)?;
        written += pblock.put(buf)?;
        Ok(written)
    }

    /// Encode the `with-list-and-first-pblock` alternative.
    pub fn put_with_list_and_first_pblock(
        invoke: InvokeIdAndPriority,
        descriptors: &[CosemMethodDescriptor],
        pblock: &DataBlockSA<'_>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(5)?;
        written += invoke.put(buf)?;
        written += put_length(buf, descriptors.len())?;
        for desc in descriptors {
            written += desc.put(buf)?;
        }
        written += pblock.put(buf)?;
        Ok(written)
    }

    /// Encode the `with-pblock` alternative.
    pub fn put_with_pblock(
        invoke: InvokeIdAndPriority,
        pblock: &DataBlockSA<'_>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(6)?;
        written += invoke.put(buf)?;
        written += pblock.put(buf)?;
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Action-Request [195]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptor = CosemMethodDescriptor::get(buf)?;
                let method_invocation_parameters = if get_presence(buf)? {
                    Some(data_value(buf)?)
                } else {
                    None
                };
                ActionRequest::Normal {
                    invoke,
                    descriptor,
                    method_invocation_parameters,
                }
            }
            2 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
                ActionRequest::NextPblock {
                    invoke,
                    block_number,
                }
            }
            3 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptors = MethodDescriptorList::read(buf)?;
                let method_invocation_parameters = ReaderList::read(buf)?;
                ActionRequest::WithList {
                    invoke,
                    descriptors,
                    method_invocation_parameters,
                }
            }
            4 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptor = CosemMethodDescriptor::get(buf)?;
                let pblock = DataBlockSA::get(buf)?;
                ActionRequest::WithFirstPblock {
                    invoke,
                    descriptor,
                    pblock,
                }
            }
            5 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptors = MethodDescriptorList::read(buf)?;
                let pblock = DataBlockSA::get(buf)?;
                ActionRequest::WithListAndFirstPblock {
                    invoke,
                    descriptors,
                    pblock,
                }
            }
            6 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let pblock = DataBlockSA::get(buf)?;
                ActionRequest::WithPblock { invoke, pblock }
            }
            other => return Err(Error::UnknownChoice { name: "Action-Request", choice: other }),
        })
    }
}

/// Action-Response ::= [199] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionResponse<'a> {
    Normal {
        invoke: InvokeIdAndPriority,
        single_response: ActionResponseWithOptionalData<'a>,
    },
    WithPblock {
        invoke: InvokeIdAndPriority,
        pblock: DataBlockSA<'a>,
    },
    WithList {
        invoke: InvokeIdAndPriority,
        list_of_responses: ActionResponseWithOptionalDataList<'a>,
    },
    NextPblock {
        invoke: InvokeIdAndPriority,
        block_number: u32,
    },
}

impl<'a> ActionResponse<'a> {
    const TAG: u8 = 199;

    /// Encode the `normal` alternative from typed values.
    pub fn put_normal(
        invoke: InvokeIdAndPriority,
        single_response: ActionResponseWithOptionalDataWrite<'_>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(1)?;
        written += invoke.put(buf)?;
        written += single_response.put(buf)?;
        Ok(written)
    }

    /// Encode the `with-pblock` alternative.
    pub fn put_with_pblock(
        invoke: InvokeIdAndPriority,
        pblock: &DataBlockSA<'_>,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(2)?;
        written += invoke.put(buf)?;
        written += pblock.put(buf)?;
        Ok(written)
    }

    /// Encode the `with-list` alternative from typed values.
    pub fn put_with_list(
        invoke: InvokeIdAndPriority,
        list_of_responses: &[ActionResponseWithOptionalDataWrite<'_>],
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(3)?;
        written += invoke.put(buf)?;
        written += put_length(buf, list_of_responses.len())?;
        for r in list_of_responses {
            written += r.put(buf)?;
        }
        Ok(written)
    }

    /// Encode the `next-pblock` alternative.
    pub fn put_next_pblock(
        invoke: InvokeIdAndPriority,
        block_number: u32,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += buf.put_u8(4)?;
        written += invoke.put(buf)?;
        written += buf.write(&block_number.to_be_bytes())?;
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Action-Response [199]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let single_response = ActionResponseWithOptionalData::get(buf)?;
                ActionResponse::Normal {
                    invoke,
                    single_response,
                }
            }
            2 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let pblock = DataBlockSA::get(buf)?;
                ActionResponse::WithPblock { invoke, pblock }
            }
            3 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let list_of_responses = ActionResponseWithOptionalDataList::read(buf)?;
                ActionResponse::WithList {
                    invoke,
                    list_of_responses,
                }
            }
            4 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
                ActionResponse::NextPblock {
                    invoke,
                    block_number,
                }
            }
            other => return Err(Error::UnknownChoice { name: "Action-Response", choice: other }),
        })
    }
}

/// Event-Notification-Request ::= [194] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct EventNotificationRequest<'a> {
    pub time: Option<&'a [u8]>,
    pub descriptor: CosemAttributeDescriptor,
    pub attribute_value: Reader<'a>,
}

impl<'a> EventNotificationRequest<'a> {
    const TAG: u8 = 194;

    /// Encode an event-notification request from typed values.
    pub fn put(
        time: Option<&[u8]>,
        descriptor: CosemAttributeDescriptor,
        attribute_value: &dyn Codec,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += put_presence(buf, time.is_some())?;
        if let Some(t) = time {
            written += crate::axdr::put_octet_string(buf, t)?;
        }
        written += descriptor.put(buf)?;
        written += attribute_value.put(buf)?;
        Ok(written)
    }


    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Event-Notification-Request [194]", actual: tag });
        }
        let time = if get_presence(buf)? {
            Some(crate::axdr::get_octet_string(buf)?)
        } else {
            None
        };
        let descriptor = CosemAttributeDescriptor::get(buf)?;
        let attribute_value = data_value(buf)?;
        Ok(EventNotificationRequest {
            time,
            descriptor,
            attribute_value,
        })
    }
}

/// State-Error ::= ENUMERATED { service-not-allowed (1), service-unknown (2) }.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StateError {
    ServiceNotAllowed = 1,
    ServiceUnknown = 2,
}

impl StateError {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        Ok(buf.put_u8(*self as u8)?)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        match buf.get_u8()? {
            1 => Ok(Self::ServiceNotAllowed),
            2 => Ok(Self::ServiceUnknown),
            _ => Err(Error::Message("unknown state-error")),
        }
    }
}

/// Service-Error ::= CHOICE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    /// operation-not-possible [1] IMPLICIT NULL.
    OperationNotPossible,
    /// service-not-supported [2] IMPLICIT NULL.
    ServiceNotSupported,
    /// other-reason [3] IMPLICIT NULL.
    OtherReason,
    /// pdu-too-long [4] IMPLICIT NULL.
    PduTooLong,
    /// deciphering-error [5] IMPLICIT NULL.
    DecipheringError,
    /// invocation-counter-error [6] IMPLICIT Unsigned32.
    InvocationCounterError(u32),
}

impl ServiceError {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match *self {
            ServiceError::OperationNotPossible => Ok(buf.put_u8(1)?),
            ServiceError::ServiceNotSupported => Ok(buf.put_u8(2)?),
            ServiceError::OtherReason => Ok(buf.put_u8(3)?),
            ServiceError::PduTooLong => Ok(buf.put_u8(4)?),
            ServiceError::DecipheringError => Ok(buf.put_u8(5)?),
            ServiceError::InvocationCounterError(n) => {
                let mut written = buf.put_u8(6)?;
                written += buf.write(&n.to_be_bytes())?;
                Ok(written)
            }
        }
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        match buf.get_u8()? {
            1 => Ok(Self::OperationNotPossible),
            2 => Ok(Self::ServiceNotSupported),
            3 => Ok(Self::OtherReason),
            4 => Ok(Self::PduTooLong),
            5 => Ok(Self::DecipheringError),
            6 => Ok(Self::InvocationCounterError(u32::from_be_bytes(read_n::<4>(buf)?))),
            t => Err(Error::UnknownChoice { name: "Service-Error", choice: t }),
        }
    }
}

/// Exception-Response ::= [216] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionResponse {
    pub state_error: StateError,
    pub service_error: ServiceError,
}

impl ExceptionResponse {
    const TAG: u8 = 216;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += self.state_error.put(buf)?;
        written += self.service_error.put(buf)?;
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Exception-Response [216]", actual: tag });
        }
        let state_error = StateError::get(buf)?;
        let service_error = ServiceError::get(buf)?;
        Ok(ExceptionResponse { state_error, service_error })
    }
}

/// XDLMS-APDU ::= CHOICE. Models the LN referencing GET/SET/ACTION services plus
/// event notification.
#[derive(Debug, Clone, PartialEq)]
pub enum XDLMSApdu<'a> {
    InitiateRequest(crate::apdu_sn::InitiateRequest<'a>),
    ReadRequest(crate::apdu_sn::ReadRequest<'a>),
    WriteRequest(crate::apdu_sn::WriteRequest<'a>),
    InitiateResponse(crate::apdu_sn::InitiateResponse),
    ReadResponse(crate::apdu_sn::ReadResponse<'a>),
    WriteResponse(crate::apdu_sn::WriteResponse<'a>),
    ConfirmedServiceError(crate::apdu_sn::ConfirmedServiceError),
    DataNotification(crate::apdu_sn::DataNotification<'a>),
    DataNotificationConfirm(crate::apdu_sn::DataNotificationConfirm<'a>),
    UnconfirmedWriteRequest(crate::apdu_sn::UnconfirmedWriteRequest<'a>),
    InformationReportRequest(crate::apdu_sn::InformationReportRequest<'a>),
    GetRequest(GetRequest<'a>),
    GetResponse(GetResponse<'a>),
    SetRequest(SetRequest<'a>),
    SetResponse(SetResponse<'a>),
    ActionRequest(ActionRequest<'a>),
    ActionResponse(ActionResponse<'a>),
    EventNotificationRequest(EventNotificationRequest<'a>),
    ExceptionResponse(ExceptionResponse),
}

impl<'a> XDLMSApdu<'a> {
    /// Decode from a buffer; detects the APDU by its leading tag byte.
    pub fn get(buf: &mut Reader<'a>) -> Result<Self> {
        use crate::apdu_sn::{
            ConfirmedServiceError, DataNotification, DataNotificationConfirm,
            InformationReportRequest, InitiateRequest, InitiateResponse, ReadRequest, ReadResponse,
            UnconfirmedWriteRequest, WriteRequest, WriteResponse,
        };
        match buf.peek(1)?.first().copied() {
            Some(InitiateRequest::TAG) => {
                Ok(XDLMSApdu::InitiateRequest(InitiateRequest::get(buf)?))
            }
            Some(ReadRequest::TAG) => Ok(XDLMSApdu::ReadRequest(ReadRequest::get(buf)?)),
            Some(WriteRequest::TAG) => Ok(XDLMSApdu::WriteRequest(WriteRequest::get(buf)?)),
            Some(InitiateResponse::TAG) => {
                Ok(XDLMSApdu::InitiateResponse(InitiateResponse::get(buf)?))
            }
            Some(ReadResponse::TAG) => Ok(XDLMSApdu::ReadResponse(ReadResponse::get(buf)?)),
            Some(WriteResponse::TAG) => Ok(XDLMSApdu::WriteResponse(WriteResponse::get(buf)?)),
            Some(ConfirmedServiceError::TAG) => Ok(XDLMSApdu::ConfirmedServiceError(
                ConfirmedServiceError::get(buf)?,
            )),
            Some(DataNotification::TAG) => {
                Ok(XDLMSApdu::DataNotification(DataNotification::get(buf)?))
            }
            Some(DataNotificationConfirm::TAG) => Ok(XDLMSApdu::DataNotificationConfirm(
                DataNotificationConfirm::get(buf)?,
            )),
            Some(UnconfirmedWriteRequest::TAG) => Ok(XDLMSApdu::UnconfirmedWriteRequest(
                UnconfirmedWriteRequest::get(buf)?,
            )),
            Some(InformationReportRequest::TAG) => Ok(XDLMSApdu::InformationReportRequest(
                InformationReportRequest::get(buf)?,
            )),
            Some(GetRequest::TAG) => Ok(XDLMSApdu::GetRequest(GetRequest::get(buf)?)),
            Some(GetResponse::TAG) => Ok(XDLMSApdu::GetResponse(GetResponse::get(buf)?)),
            Some(SetRequest::TAG) => Ok(XDLMSApdu::SetRequest(SetRequest::get(buf)?)),
            Some(EventNotificationRequest::TAG) => Ok(XDLMSApdu::EventNotificationRequest(
                EventNotificationRequest::get(buf)?,
            )),
            Some(ActionRequest::TAG) => Ok(XDLMSApdu::ActionRequest(ActionRequest::get(buf)?)),
            Some(SetResponse::TAG) => Ok(XDLMSApdu::SetResponse(SetResponse::get(buf)?)),
            Some(ActionResponse::TAG) => Ok(XDLMSApdu::ActionResponse(ActionResponse::get(buf)?)),
            Some(ExceptionResponse::TAG) => Ok(XDLMSApdu::ExceptionResponse(ExceptionResponse::get(buf)?)),
            Some(t) => Err(Error::UnknownTag { name: "xDLMS-APDU", tag: t }),
            None => Err(Error::Message("empty xDLMS-APDU")),
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Data;

    /// Encode a typed [`Codec`] value into a fresh byte vector (test helper).
    fn enc(codec: &dyn Codec) -> Vec<u8> {
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            codec.put(&mut buf).unwrap()
        };
        backing[..n].to_vec()
    }

    /// Minimal typed value for exercising the asymmetric write helpers: wraps a
    /// [`Data`] so it can be passed as `&dyn Codec`.
    struct TestCodec(Data<'static>);

    impl Codec for TestCodec {
        fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
            self.0.put(buf)
        }

        fn assign(&mut self, _data: &Data<'_>) -> Result<()> {
            Ok(())
        }
    }

    /// Encode via a write helper, decode via `get`, then run `$assert` on the
    /// decoded value.
    macro_rules! roundtrip {
        ($put:expr, $get:path, $assert:expr) => {{
            let mut backing = [0u8; 4096];
            let n = {
                let mut buf = ByteBuffer::new(&mut backing);
                $put(&mut buf).unwrap()
            };
            let bytes = &backing[..n];
            let mut r = Reader::new(bytes);
            let decoded = $get(&mut r).unwrap();
            assert_eq!(r.pos(), bytes.len(), "message not fully consumed");
            $assert(decoded);
        }};
    }

    fn descriptor() -> CosemAttributeDescriptor {
        CosemAttributeDescriptor {
            class_id: 1,
            instance_id: [0, 0, 0, 1, 0, 8],
            attribute_id: 2,
        }
    }

    #[test]
    fn invoke_id_and_priority_bits() {
        let i = InvokeIdAndPriority::from_bits(5, true, false);
        assert_eq!(i.invoke_id(), 5);
        assert!(i.is_confirmed());
        assert!(!i.is_high_priority());
    }

    #[test]
    fn get_request_normal_roundtrip() {
        roundtrip!(
            |buf| GetRequest::put_normal(
                InvokeIdAndPriority::from_bits(1, true, false),
                descriptor(),
                None,
                buf,
            ),
            GetRequest::get,
            |d| match d {
                GetRequest::Normal { invoke, descriptor: desc, access_selection: None } => {
                    assert_eq!(invoke, InvokeIdAndPriority::from_bits(1, true, false));
                    assert_eq!(desc, descriptor());
                }
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn get_request_normal_with_selection_roundtrip() {
        let value = TestCodec(Data::Unsigned(5));
        let sel = SelectiveAccessDescriptorWrite { access_selector: 1, access_parameters: &value };
        roundtrip!(
            |buf| GetRequest::put_normal(
                InvokeIdAndPriority::from_bits(2, true, false),
                descriptor(),
                Some(sel),
                buf,
            ),
            GetRequest::get,
            |d| match d {
                GetRequest::Normal { access_selection: Some(s), .. } => {
                    assert_eq!(s.access_selector, 1);
                    assert_eq!(s.access_parameters.as_bytes(), enc(&TestCodec(Data::Unsigned(5))).as_slice());
                }
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn get_request_with_list_roundtrip() {
        roundtrip!(
            |buf| GetRequest::put_with_list(
                InvokeIdAndPriority::from_bits(3, true, false),
                &[(descriptor(), None), (descriptor(), None)],
                buf,
            ),
            GetRequest::get,
            |d| match d {
                GetRequest::WithList { descriptors, .. } => assert_eq!(descriptors.len(), 2),
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn get_response_normal_roundtrip() {
        let value = TestCodec(Data::Long64(123456789));
        roundtrip!(
            |buf| GetResponse::put_normal(
                InvokeIdAndPriority::from_bits(1, true, false),
                GetDataResultWrite::Data(&value),
                buf,
            ),
            GetResponse::get,
            |d| match d {
                GetResponse::Normal { result: GetDataResult::Data(reader), .. } => {
                    assert_eq!(reader.as_bytes(), enc(&TestCodec(Data::Long64(123456789))).as_slice());
                }
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn xdlms_apdu_dispatch_roundtrip() {
        roundtrip!(
            |buf| GetResponse::put_normal(
                InvokeIdAndPriority::from_bits(1, true, false),
                GetDataResultWrite::DataAccessError(DataAccessResult::ObjectUnavailable),
                buf,
            ),
            XDLMSApdu::get,
            |d| match d {
                XDLMSApdu::GetResponse(GetResponse::Normal {
                    result: GetDataResult::DataAccessError(DataAccessResult::ObjectUnavailable),
                    ..
                }) => {}
                _ => panic!("wrong variant"),
            }
        );
    }

    fn method_descriptor() -> CosemMethodDescriptor {
        CosemMethodDescriptor {
            class_id: 7,
            instance_id: [0, 0, 1, 0, 0, 255],
            method_id: 1,
        }
    }

    #[test]
    fn set_request_normal_roundtrip() {
        let value = TestCodec(Data::Unsigned(42));
        roundtrip!(
            |buf| SetRequest::put_normal(
                InvokeIdAndPriority::from_bits(1, true, false),
                descriptor(),
                None,
                &value,
                buf,
            ),
            SetRequest::get,
            |d| match d {
                SetRequest::Normal { value: v, .. } => {
                    assert_eq!(v.as_bytes(), enc(&TestCodec(Data::Unsigned(42))).as_slice());
                }
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn set_request_with_first_datablock_roundtrip() {
        let datablock = DataBlockSA {
            last_block: false,
            block_number: 0,
            raw_data: b"\xDE\xAD",
        };
        roundtrip!(
            |buf| SetRequest::put_with_first_datablock(
                InvokeIdAndPriority::from_bits(1, true, false),
                descriptor(),
                None,
                &datablock,
                buf,
            ),
            SetRequest::get,
            |d| match d {
                SetRequest::WithFirstDatablock { datablock: db, .. } => {
                    assert_eq!(db.raw_data, b"\xDE\xAD");
                }
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn set_request_with_list_roundtrip() {
        let v1 = TestCodec(Data::Unsigned(1));
        let v2 = TestCodec(Data::Unsigned(2));
        roundtrip!(
            |buf| SetRequest::put_with_list(
                InvokeIdAndPriority::from_bits(1, true, false),
                &[(descriptor(), None), (descriptor(), None)],
                &[&v1, &v2],
                buf,
            ),
            SetRequest::get,
            |d| match d {
                SetRequest::WithList { mut values, .. } => {
                    assert_eq!(values.len(), 2);
                    assert_eq!(values.next().unwrap().unwrap().as_bytes(), enc(&TestCodec(Data::Unsigned(1))).as_slice());
                    assert_eq!(values.next().unwrap().unwrap().as_bytes(), enc(&TestCodec(Data::Unsigned(2))).as_slice());
                    assert!(values.next().is_none());
                }
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn set_response_normal_roundtrip() {
        roundtrip!(
            |buf| SetResponse::put_normal(
                InvokeIdAndPriority::from_bits(1, true, false),
                DataAccessResult::Success,
                buf,
            ),
            SetResponse::get,
            |d| match d {
                SetResponse::Normal { result: DataAccessResult::Success, .. } => {}
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn set_response_with_list_roundtrip() {
        roundtrip!(
            |buf| SetResponse::put_with_list(
                InvokeIdAndPriority::from_bits(1, true, false),
                &[DataAccessResult::Success, DataAccessResult::Success],
                buf,
            ),
            SetResponse::get,
            |d| match d {
                SetResponse::WithList { results, .. } => assert_eq!(results.len(), 2),
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn action_request_normal_roundtrip() {
        let params = TestCodec(Data::Unsigned(7));
        roundtrip!(
            |buf| ActionRequest::put_normal(
                InvokeIdAndPriority::from_bits(1, true, false),
                method_descriptor(),
                Some(&params),
                buf,
            ),
            ActionRequest::get,
            |d| match d {
                ActionRequest::Normal { method_invocation_parameters: Some(p), .. } => {
                    assert_eq!(p.as_bytes(), enc(&TestCodec(Data::Unsigned(7))).as_slice());
                }
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn action_request_with_list_roundtrip() {
        let p1 = TestCodec(Data::Unsigned(1));
        let p2 = TestCodec(Data::Unsigned(2));
        roundtrip!(
            |buf| ActionRequest::put_with_list(
                InvokeIdAndPriority::from_bits(1, true, false),
                &[method_descriptor()],
                &[&p1, &p2],
                buf,
            ),
            ActionRequest::get,
            |d| match d {
                ActionRequest::WithList { method_invocation_parameters, .. } => {
                    assert_eq!(method_invocation_parameters.len(), 2);
                }
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn action_response_normal_roundtrip() {
        roundtrip!(
            |buf| ActionResponse::put_normal(
                InvokeIdAndPriority::from_bits(1, true, false),
                ActionResponseWithOptionalDataWrite { result: 0, return_parameters: None },
                buf,
            ),
            ActionResponse::get,
            |d| match d {
                ActionResponse::Normal { single_response, .. } => {
                    assert_eq!(single_response.result, 0);
                    assert!(single_response.return_parameters.is_none());
                }
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn event_notification_roundtrip() {
        let value = TestCodec(Data::Unsigned(1));
        roundtrip!(
            |buf| EventNotificationRequest::put(
                Some(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"),
                descriptor(),
                &value,
                buf,
            ),
            EventNotificationRequest::get,
            |d: EventNotificationRequest| {
                assert_eq!(d.time, Some(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c".as_slice()));
                assert_eq!(d.attribute_value.as_bytes(), enc(&TestCodec(Data::Unsigned(1))).as_slice());
            }
        );
    }

    #[test]
    fn xdlms_apdu_set_action_dispatch_roundtrip() {
        let value = TestCodec(Data::Unsigned(9));
        roundtrip!(
            |buf| SetRequest::put_normal(
                InvokeIdAndPriority::from_bits(1, true, false),
                descriptor(),
                None,
                &value,
                buf,
            ),
            XDLMSApdu::get,
            |d| match d {
                XDLMSApdu::SetRequest(SetRequest::Normal { value: v, .. }) => {
                    assert_eq!(v.as_bytes(), enc(&TestCodec(Data::Unsigned(9))).as_slice());
                }
                _ => panic!("wrong variant"),
            }
        );
    }

    #[test]
    fn exception_response_roundtrip() {
        let resp = ExceptionResponse {
            state_error: StateError::ServiceNotAllowed,
            service_error: ServiceError::InvocationCounterError(42),
        };
        roundtrip!(
            |buf| resp.put(buf),
            ExceptionResponse::get,
            |d: ExceptionResponse| {
                assert_eq!(d.state_error, StateError::ServiceNotAllowed);
                assert_eq!(d.service_error, ServiceError::InvocationCounterError(42));
            }
        );
    }

    #[test]
    fn xdlms_apdu_exception_response_dispatch_roundtrip() {
        let resp = ExceptionResponse {
            state_error: StateError::ServiceUnknown,
            service_error: ServiceError::PduTooLong,
        };
        roundtrip!(
            |buf| resp.put(buf),
            XDLMSApdu::get,
            |d| match d {
                XDLMSApdu::ExceptionResponse(r) => {
                    assert_eq!(r.state_error, StateError::ServiceUnknown);
                    assert_eq!(r.service_error, ServiceError::PduTooLong);
                }
                _ => panic!("wrong variant"),
            }
        );
    }
}
