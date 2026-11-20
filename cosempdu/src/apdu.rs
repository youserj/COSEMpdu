//! xDLMS APDU types with A-XDR encoding (IEC 61334-6).
//!
//! Mirrors the confirmed GET/SET/ACTION (LN referencing) and SN-referencing
//! services from `src/COSEMpdu/apdu.py` (Green Book 8.3). The complete xDLMS
//! APDU is a large CHOICE; this module implements the most commonly used
//! services plus the [`XDLMSApdu`] dispatch type.

use crate::axdr::{get_length, put_length};
use crate::data::{data_value, Codec};
use crate::error::{Error, Result};
use bytebuffer::{ByteBuffer, Reader, WriteBuf};

pub trait ImplicitTagged<'a>: Sized {
    const TAG: u8;

    fn validate_tag(buf: &mut Reader<'a>) -> Result<()> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::TagNumber {
                expected: Self::TAG,
                actual: tag,
            });
        }
        Ok(())
    }

    /// Decode a full APDU: validate the IMPLICIT tag byte, then the content.
    fn get(buf: &mut Reader<'a>) -> Result<Self> {
        Self::validate_tag(buf)?;
        Self::decode(buf)
    }

    /// Decode the content that follows the tag byte.
    fn decode(buf: &mut Reader<'a>) -> Result<Self>;
}

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

    fn put<B: WriteBuf>(&self, buf: &mut B) -> Result<usize> {
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
fn put_presence<B: WriteBuf>(buf: &mut B, present: bool) -> Result<usize> {
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
        Ok(DescriptorList {
            count,
            buf: Reader::new(buf.read_at(start, end - start)?),
        })
    }

    fn decode_one(
        buf: &mut Reader<'a>,
    ) -> Result<(
        CosemAttributeDescriptor,
        Option<SelectiveAccessDescriptor<'a>>,
    )> {
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
    type Item = Result<(
        CosemAttributeDescriptor,
        Option<SelectiveAccessDescriptor<'a>>,
    )>;

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
        Ok(MethodDescriptorList {
            count,
            buf: Reader::new(buf.read_at(start, end - start)?),
        })
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
        Ok(ReaderList {
            count,
            buf: Reader::new(buf.read_at(start, end - start)?),
        })
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
        Ok(GetDataResultList {
            count,
            buf: Reader::new(buf.read_at(start, end - start)?),
        })
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

#[derive(Debug, Clone, PartialEq)]
pub struct GetRequestNormal<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptor: CosemAttributeDescriptor,
    pub access_selection: Option<SelectiveAccessDescriptor<'a>>,
}

impl<'a> ImplicitTagged<'a> for GetRequestNormal<'a> {
    const TAG: u8 = 1;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptor = CosemAttributeDescriptor::get(buf)?;
        let access_selection = if get_presence(buf)? {
            Some(SelectiveAccessDescriptor::get(buf)?)
        } else {
            None
        };
        Ok(Self {
            invoke,
            descriptor,
            access_selection,
        })
    }
}

/// get-request-next [2] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct GetRequestNext {
    pub invoke: InvokeIdAndPriority,
    pub block_number: u32,
}

impl<'a> ImplicitTagged<'a> for GetRequestNext {
    const TAG: u8 = 2;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
        Ok(GetRequestNext {
            invoke,
            block_number,
        })
    }
}

/// get-request-with-list [3] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct GetRequestWithList<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptors: DescriptorList<'a>,
}

impl<'a> ImplicitTagged<'a> for GetRequestWithList<'a> {
    const TAG: u8 = 3;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptors = DescriptorList::read(buf)?;
        Ok(GetRequestWithList {
            invoke,
            descriptors,
        })
    }
}

/// Get-Request ::= [192] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum GetRequest<'a> {
    Normal(GetRequestNormal<'a>),
    Next(GetRequestNext),
    WithList(GetRequestWithList<'a>),
}

impl<'a> ImplicitTagged<'a> for GetRequest<'a> {
    const TAG: u8 = 192;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(match buf.get_u8()? {
            GetRequestNormal::TAG => GetRequest::Normal(GetRequestNormal::decode(buf)?),
            2 => GetRequest::Next(GetRequestNext::decode(buf)?),
            3 => GetRequest::WithList(GetRequestWithList::decode(buf)?),
            other => return Err(Error::UnknownTag { tag: other }),
        })
    }
}

impl<'a> GetRequest<'a> {
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
        descriptors: &[(
            CosemAttributeDescriptor,
            Option<SelectiveAccessDescriptorWrite<'_>>,
        )],
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
    pub fn put<B: WriteBuf>(&self, buf: &mut B) -> Result<usize> {
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
            t => Err(Error::UnknownTag { tag: t }),
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
            0 => Ok(DataBlockGResult::RawData(crate::axdr::get_octet_string(
                buf,
            )?)),
            1 => Ok(DataBlockGResult::DataAccessError(DataAccessResult::get(
                buf,
            )?)),
            t => Err(Error::UnknownTag { tag: t }),
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

/// get-response-normal [1] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct GetResponseNormal<'a> {
    pub invoke: InvokeIdAndPriority,
    pub result: GetDataResult<'a>,
}

impl<'a> ImplicitTagged<'a> for GetResponseNormal<'a> {
    const TAG: u8 = 1;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let result = GetDataResult::get(buf)?;
        Ok(GetResponseNormal { invoke, result })
    }
}

/// get-response-with-datablock [2] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct GetResponseWithDatablock<'a> {
    pub invoke: InvokeIdAndPriority,
    pub result: DataBlockG<'a>,
}

impl<'a> ImplicitTagged<'a> for GetResponseWithDatablock<'a> {
    const TAG: u8 = 2;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let result = DataBlockG::get(buf)?;
        Ok(GetResponseWithDatablock { invoke, result })
    }
}

/// get-response-with-list [3] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct GetResponseWithList<'a> {
    pub invoke: InvokeIdAndPriority,
    pub results: GetDataResultList<'a>,
}

impl<'a> ImplicitTagged<'a> for GetResponseWithList<'a> {
    const TAG: u8 = 3;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let results = GetDataResultList::read(buf)?;
        Ok(GetResponseWithList { invoke, results })
    }
}

/// Get-Response ::= [196] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum GetResponse<'a> {
    Normal(GetResponseNormal<'a>),
    WithDatablock(GetResponseWithDatablock<'a>),
    WithList(GetResponseWithList<'a>),
}

impl<'a> GetResponse<'a> {
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
}

impl<'a> ImplicitTagged<'a> for GetResponse<'a> {
    const TAG: u8 = 196;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(match buf.peek_u8()? {
            1 => GetResponse::Normal(GetResponseNormal::get(buf)?),
            2 => GetResponse::WithDatablock(GetResponseWithDatablock::get(buf)?),
            3 => GetResponse::WithList(GetResponseWithList::get(buf)?),
            other => return Err(Error::UnknownTag { tag: other }),
        })
    }
}

/// set-request-normal [1] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct SetRequestNormal<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptor: CosemAttributeDescriptor,
    pub access_selection: Option<SelectiveAccessDescriptor<'a>>,
    pub value: Reader<'a>,
}

impl<'a> ImplicitTagged<'a> for SetRequestNormal<'a> {
    const TAG: u8 = 1;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptor = CosemAttributeDescriptor::get(buf)?;
        let access_selection = if get_presence(buf)? {
            Some(SelectiveAccessDescriptor::get(buf)?)
        } else {
            None
        };
        let value = data_value(buf)?;
        Ok(SetRequestNormal {
            invoke,
            descriptor,
            access_selection,
            value,
        })
    }
}

/// set-request-with-first-datablock [2] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct SetRequestWithFirstDatablock<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptor: CosemAttributeDescriptor,
    pub access_selection: Option<SelectiveAccessDescriptor<'a>>,
    pub datablock: DataBlockSA<'a>,
}

impl<'a> ImplicitTagged<'a> for SetRequestWithFirstDatablock<'a> {
    const TAG: u8 = 2;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptor = CosemAttributeDescriptor::get(buf)?;
        let access_selection = if get_presence(buf)? {
            Some(SelectiveAccessDescriptor::get(buf)?)
        } else {
            None
        };
        let datablock = DataBlockSA::get(buf)?;
        Ok(SetRequestWithFirstDatablock {
            invoke,
            descriptor,
            access_selection,
            datablock,
        })
    }
}

/// set-request-with-datablock [3] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct SetRequestWithDatablock<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptor: CosemAttributeDescriptor,
    pub access_selection: Option<SelectiveAccessDescriptor<'a>>,
    pub datablock: DataBlockSA<'a>,
}

impl<'a> ImplicitTagged<'a> for SetRequestWithDatablock<'a> {
    const TAG: u8 = 3;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptor = CosemAttributeDescriptor::get(buf)?;
        let access_selection = if get_presence(buf)? {
            Some(SelectiveAccessDescriptor::get(buf)?)
        } else {
            None
        };
        let datablock = DataBlockSA::get(buf)?;
        Ok(SetRequestWithDatablock {
            invoke,
            descriptor,
            access_selection,
            datablock,
        })
    }
}

/// set-request-with-list [4] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct SetRequestWithList<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptors: DescriptorList<'a>,
    pub values: ReaderList<'a>,
}

impl<'a> ImplicitTagged<'a> for SetRequestWithList<'a> {
    const TAG: u8 = 4;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptors = DescriptorList::read(buf)?;
        let values = ReaderList::read(buf)?;
        Ok(SetRequestWithList {
            invoke,
            descriptors,
            values,
        })
    }
}

/// set-request-with-list-and-first-datablock [5] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct SetRequestWithListAndFirstDatablock<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptors: DescriptorList<'a>,
    pub datablock: DataBlockSA<'a>,
}

impl<'a> ImplicitTagged<'a> for SetRequestWithListAndFirstDatablock<'a> {
    const TAG: u8 = 5;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptors = DescriptorList::read(buf)?;
        let datablock = DataBlockSA::get(buf)?;
        Ok(SetRequestWithListAndFirstDatablock {
            invoke,
            descriptors,
            datablock,
        })
    }
}

/// Set-Request ::= [193] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum SetRequest<'a> {
    Normal(SetRequestNormal<'a>),
    WithFirstDatablock(SetRequestWithFirstDatablock<'a>),
    WithDatablock(SetRequestWithDatablock<'a>),
    WithList(SetRequestWithList<'a>),
    WithListAndFirstDatablock(SetRequestWithListAndFirstDatablock<'a>),
}

impl<'a> SetRequest<'a> {
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
        descriptors: &[(
            CosemAttributeDescriptor,
            Option<SelectiveAccessDescriptorWrite<'_>>,
        )],
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
        descriptors: &[(
            CosemAttributeDescriptor,
            Option<SelectiveAccessDescriptorWrite<'_>>,
        )],
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
}

impl<'a> ImplicitTagged<'a> for SetRequest<'a> {
    const TAG: u8 = 193;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(match buf.peek_u8()? {
            1 => SetRequest::Normal(SetRequestNormal::get(buf)?),
            2 => SetRequest::WithFirstDatablock(SetRequestWithFirstDatablock::get(buf)?),
            3 => SetRequest::WithDatablock(SetRequestWithDatablock::get(buf)?),
            4 => SetRequest::WithList(SetRequestWithList::get(buf)?),
            5 => SetRequest::WithListAndFirstDatablock(SetRequestWithListAndFirstDatablock::get(
                buf,
            )?),
            other => return Err(Error::UnknownTag { tag: other }),
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
        Ok(DataAccessResultList {
            count,
            buf: Reader::new(buf.read_at(start, end - start)?),
        })
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

/// set-response-normal [1] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct SetResponseNormal {
    pub invoke: InvokeIdAndPriority,
    pub result: DataAccessResult,
}

impl<'a> ImplicitTagged<'a> for SetResponseNormal {
    const TAG: u8 = 1;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let result = DataAccessResult::get(buf)?;
        Ok(SetResponseNormal { invoke, result })
    }
}

/// set-response-datablock [2] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct SetResponseDatablock {
    pub invoke: InvokeIdAndPriority,
    pub block_number: u32,
}

impl<'a> ImplicitTagged<'a> for SetResponseDatablock {
    const TAG: u8 = 2;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
        Ok(SetResponseDatablock {
            invoke,
            block_number,
        })
    }
}

/// set-response-last-datablock [3] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct SetResponseLastDatablock {
    pub invoke: InvokeIdAndPriority,
    pub result: DataAccessResult,
    pub block_number: u32,
}

impl<'a> ImplicitTagged<'a> for SetResponseLastDatablock {
    const TAG: u8 = 3;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let result = DataAccessResult::get(buf)?;
        let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
        Ok(SetResponseLastDatablock {
            invoke,
            result,
            block_number,
        })
    }
}

/// set-response-last-datablock-with-list [4] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct SetResponseLastDatablockWithList {
    pub invoke: InvokeIdAndPriority,
    pub block_number: u32,
}

impl<'a> ImplicitTagged<'a> for SetResponseLastDatablockWithList {
    const TAG: u8 = 4;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
        Ok(SetResponseLastDatablockWithList {
            invoke,
            block_number,
        })
    }
}

/// set-response-with-list [5] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct SetResponseWithList<'a> {
    pub invoke: InvokeIdAndPriority,
    pub results: DataAccessResultList<'a>,
}

impl<'a> ImplicitTagged<'a> for SetResponseWithList<'a> {
    const TAG: u8 = 5;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let results = DataAccessResultList::read(buf)?;
        Ok(SetResponseWithList { invoke, results })
    }
}

/// Set-Response ::= [197] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum SetResponse<'a> {
    Normal(SetResponseNormal),
    Datablock(SetResponseDatablock),
    LastDatablock(SetResponseLastDatablock),
    LastDatablockWithList(SetResponseLastDatablockWithList),
    WithList(SetResponseWithList<'a>),
}

impl<'a> SetResponse<'a> {
    /// Encode the `normal` alternative.
    pub fn put_normal<B: WriteBuf>(
        invoke: InvokeIdAndPriority,
        result: DataAccessResult,
        buf: &mut B,
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
}

impl<'a> ImplicitTagged<'a> for SetResponse<'a> {
    const TAG: u8 = 197;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(match buf.peek_u8()? {
            1 => SetResponse::Normal(SetResponseNormal::get(buf)?),
            2 => SetResponse::Datablock(SetResponseDatablock::get(buf)?),
            3 => SetResponse::LastDatablock(SetResponseLastDatablock::get(buf)?),
            4 => SetResponse::LastDatablockWithList(SetResponseLastDatablockWithList::get(buf)?),
            5 => SetResponse::WithList(SetResponseWithList::get(buf)?),
            other => return Err(Error::UnknownTag { tag: other }),
        })
    }
}

/// action-request-normal [1] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequestNormal<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptor: CosemMethodDescriptor,
    pub method_invocation_parameters: Option<Reader<'a>>,
}

impl<'a> ImplicitTagged<'a> for ActionRequestNormal<'a> {
    const TAG: u8 = 1;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptor = CosemMethodDescriptor::get(buf)?;
        let method_invocation_parameters = if get_presence(buf)? {
            Some(data_value(buf)?)
        } else {
            None
        };
        Ok(ActionRequestNormal {
            invoke,
            descriptor,
            method_invocation_parameters,
        })
    }
}

/// action-request-next-pblock [2] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequestNextPblock {
    pub invoke: InvokeIdAndPriority,
    pub block_number: u32,
}

impl<'a> ImplicitTagged<'a> for ActionRequestNextPblock {
    const TAG: u8 = 2;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
        Ok(ActionRequestNextPblock {
            invoke,
            block_number,
        })
    }
}

/// action-request-with-list [3] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequestWithList<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptors: MethodDescriptorList<'a>,
    pub method_invocation_parameters: ReaderList<'a>,
}

impl<'a> ImplicitTagged<'a> for ActionRequestWithList<'a> {
    const TAG: u8 = 3;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptors = MethodDescriptorList::read(buf)?;
        let method_invocation_parameters = ReaderList::read(buf)?;
        Ok(ActionRequestWithList {
            invoke,
            descriptors,
            method_invocation_parameters,
        })
    }
}

/// action-request-with-first-pblock [4] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequestWithFirstPblock<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptor: CosemMethodDescriptor,
    pub pblock: DataBlockSA<'a>,
}

impl<'a> ImplicitTagged<'a> for ActionRequestWithFirstPblock<'a> {
    const TAG: u8 = 4;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptor = CosemMethodDescriptor::get(buf)?;
        let pblock = DataBlockSA::get(buf)?;
        Ok(ActionRequestWithFirstPblock {
            invoke,
            descriptor,
            pblock,
        })
    }
}

/// action-request-with-list-and-first-pblock [5] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequestWithListAndFirstPblock<'a> {
    pub invoke: InvokeIdAndPriority,
    pub descriptors: MethodDescriptorList<'a>,
    pub pblock: DataBlockSA<'a>,
}

impl<'a> ImplicitTagged<'a> for ActionRequestWithListAndFirstPblock<'a> {
    const TAG: u8 = 5;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let descriptors = MethodDescriptorList::read(buf)?;
        let pblock = DataBlockSA::get(buf)?;
        Ok(ActionRequestWithListAndFirstPblock {
            invoke,
            descriptors,
            pblock,
        })
    }
}

/// action-request-with-pblock [6] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequestWithPblock<'a> {
    pub invoke: InvokeIdAndPriority,
    pub pblock: DataBlockSA<'a>,
}

impl<'a> ImplicitTagged<'a> for ActionRequestWithPblock<'a> {
    const TAG: u8 = 6;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let pblock = DataBlockSA::get(buf)?;
        Ok(ActionRequestWithPblock { invoke, pblock })
    }
}

/// Action-Request ::= [195] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionRequest<'a> {
    Normal(ActionRequestNormal<'a>),
    NextPblock(ActionRequestNextPblock),
    WithList(ActionRequestWithList<'a>),
    WithFirstPblock(ActionRequestWithFirstPblock<'a>),
    WithListAndFirstPblock(ActionRequestWithListAndFirstPblock<'a>),
    WithPblock(ActionRequestWithPblock<'a>),
}

impl<'a> ActionRequest<'a> {
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
}

impl<'a> ImplicitTagged<'a> for ActionRequest<'a> {
    const TAG: u8 = 195;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(match buf.peek_u8()? {
            1 => ActionRequest::Normal(ActionRequestNormal::get(buf)?),
            2 => ActionRequest::NextPblock(ActionRequestNextPblock::get(buf)?),
            3 => ActionRequest::WithList(ActionRequestWithList::get(buf)?),
            4 => ActionRequest::WithFirstPblock(ActionRequestWithFirstPblock::get(buf)?),
            5 => ActionRequest::WithListAndFirstPblock(ActionRequestWithListAndFirstPblock::get(
                buf,
            )?),
            6 => ActionRequest::WithPblock(ActionRequestWithPblock::get(buf)?),
            other => return Err(Error::UnknownTag { tag: other }),
        })
    }
}

/// action-response-normal [1] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionResponseNormal<'a> {
    pub invoke: InvokeIdAndPriority,
    pub single_response: ActionResponseWithOptionalData<'a>,
}

impl<'a> ImplicitTagged<'a> for ActionResponseNormal<'a> {
    const TAG: u8 = 1;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let single_response = ActionResponseWithOptionalData::get(buf)?;
        Ok(ActionResponseNormal {
            invoke,
            single_response,
        })
    }
}

/// action-response-with-pblock [2] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionResponseWithPblock<'a> {
    pub invoke: InvokeIdAndPriority,
    pub pblock: DataBlockSA<'a>,
}

impl<'a> ImplicitTagged<'a> for ActionResponseWithPblock<'a> {
    const TAG: u8 = 2;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let pblock = DataBlockSA::get(buf)?;
        Ok(ActionResponseWithPblock { invoke, pblock })
    }
}

/// action-response-with-list [3] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionResponseWithList<'a> {
    pub invoke: InvokeIdAndPriority,
    pub list_of_responses: ActionResponseWithOptionalDataList<'a>,
}

impl<'a> ImplicitTagged<'a> for ActionResponseWithList<'a> {
    const TAG: u8 = 3;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let list_of_responses = ActionResponseWithOptionalDataList::read(buf)?;
        Ok(ActionResponseWithList {
            invoke,
            list_of_responses,
        })
    }
}

/// action-response-next-pblock [4] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionResponseNextPblock {
    pub invoke: InvokeIdAndPriority,
    pub block_number: u32,
}

impl<'a> ImplicitTagged<'a> for ActionResponseNextPblock {
    const TAG: u8 = 4;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let invoke = InvokeIdAndPriority::get(buf)?;
        let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
        Ok(ActionResponseNextPblock {
            invoke,
            block_number,
        })
    }
}

/// Action-Response ::= [199] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionResponse<'a> {
    Normal(ActionResponseNormal<'a>),
    WithPblock(ActionResponseWithPblock<'a>),
    WithList(ActionResponseWithList<'a>),
    NextPblock(ActionResponseNextPblock),
}

impl<'a> ActionResponse<'a> {
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
}

impl<'a> ImplicitTagged<'a> for ActionResponse<'a> {
    const TAG: u8 = 199;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(match buf.peek_u8()? {
            1 => ActionResponse::Normal(ActionResponseNormal::get(buf)?),
            2 => ActionResponse::WithPblock(ActionResponseWithPblock::get(buf)?),
            3 => ActionResponse::WithList(ActionResponseWithList::get(buf)?),
            4 => ActionResponse::NextPblock(ActionResponseNextPblock::get(buf)?),
            other => return Err(Error::UnknownTag { tag: other }),
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
}

impl<'a> ImplicitTagged<'a> for EventNotificationRequest<'a> {
    const TAG: u8 = 194;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
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
    pub fn put<B: WriteBuf>(&self, buf: &mut B) -> Result<usize> {
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
pub enum ServiceError_ {
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

impl ServiceError_ {
    pub fn put<B: WriteBuf>(&self, buf: &mut B) -> Result<usize> {
        match *self {
            ServiceError_::OperationNotPossible => Ok(buf.put_u8(1)?),
            ServiceError_::ServiceNotSupported => Ok(buf.put_u8(2)?),
            ServiceError_::OtherReason => Ok(buf.put_u8(3)?),
            ServiceError_::PduTooLong => Ok(buf.put_u8(4)?),
            ServiceError_::DecipheringError => Ok(buf.put_u8(5)?),
            ServiceError_::InvocationCounterError(n) => {
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
            6 => Ok(Self::InvocationCounterError(u32::from_be_bytes(
                read_n::<4>(buf)?,
            ))),
            t => Err(Error::UnknownTag { tag: t }),
        }
    }
}

/// Exception-Response ::= [216] IMPLICIT SEQUENCE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionResponse {
    pub state_error: StateError,
    pub service_error: ServiceError_,
}

impl ExceptionResponse {
    pub fn put<B: WriteBuf>(&self, buf: &mut B) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += self.state_error.put(buf)?;
        written += self.service_error.put(buf)?;
        Ok(written)
    }
}

impl<'a> ImplicitTagged<'a> for ExceptionResponse {
    const TAG: u8 = 216;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        let state_error = StateError::get(buf)?;
        let service_error = ServiceError_::get(buf)?;
        Ok(ExceptionResponse {
            state_error,
            service_error,
        })
    }
}

/// Bit indices of the 24-bit conformance block (bit 0 = MSB of the first byte).
///
/// The bit is set when the corresponding service/feature is available.
pub mod conformance_bit {
    pub const RESERVED_ZERO: u8 = 0;
    pub const GENERAL_PROTECTION: u8 = 1;
    pub const GENERAL_BLOCK_TRANSFER: u8 = 2;
    pub const READ: u8 = 3;
    pub const WRITE: u8 = 4;
    pub const UNCONFIRMED_WRITE: u8 = 5;
    pub const DELTA_VALUE_ENCODING: u8 = 6;
    pub const RESERVED_SEVEN: u8 = 7;
    pub const ATTRIBUTE0_SUPPORTED_WITH_SET: u8 = 8;
    pub const PRIORITY_MGMT_SUPPORTED: u8 = 9;
    pub const ATTRIBUTE0_SUPPORTED_WITH_GET: u8 = 10;
    pub const BLOCK_TRANSFER_WITH_GET_OR_READ: u8 = 11;
    pub const BLOCK_TRANSFER_WITH_SET_OR_WRITE: u8 = 12;
    pub const BLOCK_TRANSFER_WITH_ACTION: u8 = 13;
    pub const MULTIPLE_REFERENCES: u8 = 14;
    pub const INFORMATION_REPORT: u8 = 15;
    pub const DATA_NOTIFICATION: u8 = 16;
    pub const ACCESS: u8 = 17;
    pub const PARAMETERIZED_ACCESS: u8 = 18;
    pub const GET: u8 = 19;
    pub const SET: u8 = 20;
    pub const SELECTIVE_ACCESS: u8 = 21;
    pub const EVENT_NOTIFICATION: u8 = 22;
    pub const ACTION: u8 = 23;
}

/// A set of conformance-block flags — for readable construction of [`Conformance`].
///
/// Reserved bits 0 and 7 are absent and always cleared.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConformanceBits {
    pub general_protection: bool,
    pub general_block_transfer: bool,
    pub read: bool,
    pub write: bool,
    pub unconfirmed_write: bool,
    pub delta_value_encoding: bool,
    pub attribute0_supported_with_set: bool,
    pub priority_mgmt_supported: bool,
    pub attribute0_supported_with_get: bool,
    pub block_transfer_with_get_or_read: bool,
    pub block_transfer_with_set_or_write: bool,
    pub block_transfer_with_action: bool,
    pub multiple_references: bool,
    pub information_report: bool,
    pub data_notification: bool,
    pub access: bool,
    pub parameterized_access: bool,
    pub get: bool,
    pub set: bool,
    pub selective_access: bool,
    pub event_notification: bool,
    pub action: bool,
}

/// Set bit `index` (0..24) in the 24-bit conformance block.
const fn set_conformance_bit(mut bytes: [u8; 3], index: u8) -> [u8; 3] {
    bytes[(index / 8) as usize] |= 1 << (7 - index % 8);
    bytes
}

/// `Conformance ::= [APPLICATION 31] IMPLICIT BIT STRING (SIZE(24))`.
///
/// Encoded in BER: tag (`5F 1F`) + length (`04`) + unused-bits (`00`) + 3 value
/// octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conformance(pub [u8; 3]);

impl Conformance {
    pub fn put<B: WriteBuf>(&self, buf: &mut B) -> Result<usize> {
        let mut written = buf.write(&[0x5F, 0x1F, 0x04, 0x00])?;
        written += buf.write(&self.0)?;
        Ok(written)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        let t0 = buf.get_u8()?;
        let t1 = buf.get_u8()?;
        if t0 != 0x5F || t1 != 0x1F {
            return Err(Error::UnexpectedTag {
                name: "Conformance",
                actual: t0,
            });
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

    /// Bitwise intersection (AND) with another conformance set —
    /// the negotiation result "proposed ∩ supported".
    pub fn intersection(self, other: Conformance) -> Conformance {
        Conformance([
            self.0[0] & other.0[0],
            self.0[1] & other.0[1],
            self.0[2] & other.0[2],
        ])
    }

    /// Build a conformance from a set of flags.
    pub const fn from_bits(bits: ConformanceBits) -> Self {
        let mut bytes = [0u8; 3];
        if bits.general_protection {
            bytes = set_conformance_bit(bytes, conformance_bit::GENERAL_PROTECTION);
        }
        if bits.general_block_transfer {
            bytes = set_conformance_bit(bytes, conformance_bit::GENERAL_BLOCK_TRANSFER);
        }
        if bits.read {
            bytes = set_conformance_bit(bytes, conformance_bit::READ);
        }
        if bits.write {
            bytes = set_conformance_bit(bytes, conformance_bit::WRITE);
        }
        if bits.unconfirmed_write {
            bytes = set_conformance_bit(bytes, conformance_bit::UNCONFIRMED_WRITE);
        }
        if bits.delta_value_encoding {
            bytes = set_conformance_bit(bytes, conformance_bit::DELTA_VALUE_ENCODING);
        }
        if bits.attribute0_supported_with_set {
            bytes = set_conformance_bit(bytes, conformance_bit::ATTRIBUTE0_SUPPORTED_WITH_SET);
        }
        if bits.priority_mgmt_supported {
            bytes = set_conformance_bit(bytes, conformance_bit::PRIORITY_MGMT_SUPPORTED);
        }
        if bits.attribute0_supported_with_get {
            bytes = set_conformance_bit(bytes, conformance_bit::ATTRIBUTE0_SUPPORTED_WITH_GET);
        }
        if bits.block_transfer_with_get_or_read {
            bytes = set_conformance_bit(bytes, conformance_bit::BLOCK_TRANSFER_WITH_GET_OR_READ);
        }
        if bits.block_transfer_with_set_or_write {
            bytes = set_conformance_bit(bytes, conformance_bit::BLOCK_TRANSFER_WITH_SET_OR_WRITE);
        }
        if bits.block_transfer_with_action {
            bytes = set_conformance_bit(bytes, conformance_bit::BLOCK_TRANSFER_WITH_ACTION);
        }
        if bits.multiple_references {
            bytes = set_conformance_bit(bytes, conformance_bit::MULTIPLE_REFERENCES);
        }
        if bits.information_report {
            bytes = set_conformance_bit(bytes, conformance_bit::INFORMATION_REPORT);
        }
        if bits.data_notification {
            bytes = set_conformance_bit(bytes, conformance_bit::DATA_NOTIFICATION);
        }
        if bits.access {
            bytes = set_conformance_bit(bytes, conformance_bit::ACCESS);
        }
        if bits.parameterized_access {
            bytes = set_conformance_bit(bytes, conformance_bit::PARAMETERIZED_ACCESS);
        }
        if bits.get {
            bytes = set_conformance_bit(bytes, conformance_bit::GET);
        }
        if bits.set {
            bytes = set_conformance_bit(bytes, conformance_bit::SET);
        }
        if bits.selective_access {
            bytes = set_conformance_bit(bytes, conformance_bit::SELECTIVE_ACCESS);
        }
        if bits.event_notification {
            bytes = set_conformance_bit(bytes, conformance_bit::EVENT_NOTIFICATION);
        }
        if bits.action {
            bytes = set_conformance_bit(bytes, conformance_bit::ACTION);
        }
        Conformance(bytes)
    }

    /// Check bit `index` (0..24).
    pub const fn bit(self, index: u8) -> bool {
        (self.0[(index / 8) as usize] >> (7 - index % 8)) & 1 != 0
    }

    pub const fn is_general_protection(self) -> bool {
        self.bit(conformance_bit::GENERAL_PROTECTION)
    }

    pub const fn is_general_block_transfer(self) -> bool {
        self.bit(conformance_bit::GENERAL_BLOCK_TRANSFER)
    }

    pub const fn is_read(self) -> bool {
        self.bit(conformance_bit::READ)
    }

    pub const fn is_write(self) -> bool {
        self.bit(conformance_bit::WRITE)
    }

    pub const fn is_unconfirmed_write(self) -> bool {
        self.bit(conformance_bit::UNCONFIRMED_WRITE)
    }

    pub const fn is_delta_value_encoding(self) -> bool {
        self.bit(conformance_bit::DELTA_VALUE_ENCODING)
    }

    pub const fn is_attribute0_supported_with_set(self) -> bool {
        self.bit(conformance_bit::ATTRIBUTE0_SUPPORTED_WITH_SET)
    }

    pub const fn is_priority_mgmt_supported(self) -> bool {
        self.bit(conformance_bit::PRIORITY_MGMT_SUPPORTED)
    }

    pub const fn is_attribute0_supported_with_get(self) -> bool {
        self.bit(conformance_bit::ATTRIBUTE0_SUPPORTED_WITH_GET)
    }

    pub const fn is_block_transfer_with_get_or_read(self) -> bool {
        self.bit(conformance_bit::BLOCK_TRANSFER_WITH_GET_OR_READ)
    }

    pub const fn is_block_transfer_with_set_or_write(self) -> bool {
        self.bit(conformance_bit::BLOCK_TRANSFER_WITH_SET_OR_WRITE)
    }

    pub const fn is_block_transfer_with_action(self) -> bool {
        self.bit(conformance_bit::BLOCK_TRANSFER_WITH_ACTION)
    }

    pub const fn is_multiple_references(self) -> bool {
        self.bit(conformance_bit::MULTIPLE_REFERENCES)
    }

    pub const fn is_information_report(self) -> bool {
        self.bit(conformance_bit::INFORMATION_REPORT)
    }

    pub const fn is_data_notification(self) -> bool {
        self.bit(conformance_bit::DATA_NOTIFICATION)
    }

    pub const fn is_access(self) -> bool {
        self.bit(conformance_bit::ACCESS)
    }

    pub const fn is_parameterized_access(self) -> bool {
        self.bit(conformance_bit::PARAMETERIZED_ACCESS)
    }

    pub const fn is_get(self) -> bool {
        self.bit(conformance_bit::GET)
    }

    pub const fn is_set(self) -> bool {
        self.bit(conformance_bit::SET)
    }

    pub const fn is_selective_access(self) -> bool {
        self.bit(conformance_bit::SELECTIVE_ACCESS)
    }

    pub const fn is_event_notification(self) -> bool {
        self.bit(conformance_bit::EVENT_NOTIFICATION)
    }

    pub const fn is_action(self) -> bool {
        self.bit(conformance_bit::ACTION)
    }
}

/// `ObjectName ::= Integer16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectName(pub u16);

impl ObjectName {
    pub fn put<B: WriteBuf>(&self, buf: &mut B) -> Result<usize> {
        Ok(buf.write(&self.0.to_be_bytes())?)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(ObjectName(u16::from_be_bytes([
            buf.get_u8()?,
            buf.get_u8()?,
        ])))
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
        Ok(BlockNumberAccess {
            block_number: get_u16(buf)?,
        })
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
    VariableName(ObjectName),                     // [2]
    ParameterizedAccess(ParameterizedAccess<'a>), // [4]
    BlockNumberAccess(BlockNumberAccess),         // [5]
    ReadDataBlockAccess(ReadDataBlockAccess<'a>), // [6]
    WriteDataBlockAccess(WriteDataBlockAccess),   // [7]
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
            2 => Ok(VariableAccessSpecification::VariableName(ObjectName::get(
                buf,
            )?)),
            4 => Ok(VariableAccessSpecification::ParameterizedAccess(
                ParameterizedAccess::get(buf)?,
            )),
            5 => Ok(VariableAccessSpecification::BlockNumberAccess(
                BlockNumberAccess::get(buf)?,
            )),
            6 => Ok(VariableAccessSpecification::ReadDataBlockAccess(
                ReadDataBlockAccess::get(buf)?,
            )),
            7 => Ok(VariableAccessSpecification::WriteDataBlockAccess(
                WriteDataBlockAccess::get(buf)?,
            )),
            t => Err(Error::UnknownTag { tag: t }),
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
        Ok(VariableAccessSpecificationList {
            count,
            buf: Reader::new(buf.read_at(start, end - start)?),
        })
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
    Data(Reader<'a>),                     // [0]
    DataAccessError(DataAccessResult),    // [1]
    DataBlockResult(DataBlockResult<'a>), // [2]
    BlockNumber(u16),                     // [3]
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
            1 => Ok(ReadResponseItem::DataAccessError(DataAccessResult::get(
                buf,
            )?)),
            2 => Ok(ReadResponseItem::DataBlockResult(DataBlockResult::get(
                buf,
            )?)),
            3 => Ok(ReadResponseItem::BlockNumber(get_u16(buf)?)),
            t => Err(Error::UnknownTag { tag: t }),
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
        Ok(ReadResponseItemList {
            count,
            buf: Reader::new(buf.read_at(start, end - start)?),
        })
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
    Success,                           // [0] IMPLICIT NULL
    DataAccessError(DataAccessResult), // [1]
    BlockNumber(u16),                  // [2]
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
            1 => Ok(WriteResponseItem::DataAccessError(DataAccessResult::get(
                buf,
            )?)),
            2 => Ok(WriteResponseItem::BlockNumber(get_u16(buf)?)),
            t => Err(Error::UnknownTag { tag: t }),
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
        Ok(WriteResponseItemList {
            count,
            buf: Reader::new(buf.read_at(start, end - start)?),
        })
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

/// Generates an `IMPLICIT ENUMERATED` (1-byte code without tag) with `put`/`get`.
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

/// `SnServiceError ::= CHOICE` of `IMPLICIT ENUMERATED` alternatives.
///
/// Each variant carries the `IMPLICIT ENUMERATED` code of the corresponding
/// CHOICE alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnServiceError {
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

impl SnServiceError {
    pub fn put<B: WriteBuf>(&self, buf: &mut B) -> Result<usize> {
        let (tag, value) = match *self {
            SnServiceError::ApplicationReference(v) => (0, v as u8),
            SnServiceError::HardwareResource(v) => (1, v as u8),
            SnServiceError::VdeStateError(v) => (2, v as u8),
            SnServiceError::Service(v) => (3, v as u8),
            SnServiceError::Definition(v) => (4, v as u8),
            SnServiceError::Access(v) => (5, v as u8),
            SnServiceError::Initiate(v) => (6, v as u8),
            SnServiceError::LoadDataSet(v) => (7, v as u8),
            SnServiceError::Task(v) => (9, v as u8),
        };
        let mut w = buf.put_u8(tag)?;
        w += buf.put_u8(value)?;
        Ok(w)
    }

    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        Ok(match buf.get_u8()? {
            0 => SnServiceError::ApplicationReference(ApplicationReference::get(buf)?),
            1 => SnServiceError::HardwareResource(HardwareResource::get(buf)?),
            2 => SnServiceError::VdeStateError(VdeStateError::get(buf)?),
            3 => SnServiceError::Service(Service::get(buf)?),
            4 => SnServiceError::Definition(Definition::get(buf)?),
            5 => SnServiceError::Access(Access::get(buf)?),
            6 => SnServiceError::Initiate(Initiate::get(buf)?),
            7 => SnServiceError::LoadDataSet(LoadDataSet::get(buf)?),
            9 => SnServiceError::Task(Task::get(buf)?),
            t => return Err(Error::UnknownTag { tag: t }),
        })
    }
}

/// `ConfirmedServiceError ::= CHOICE { initiateError [1] SnServiceError, ... }`.
///
/// `tag` is the service that failed (`1`..`19`); `service_error` is the
/// corresponding [`SnServiceError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedServiceError {
    pub tag: u8,
    pub service_error: SnServiceError,
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
    pub fn put<B: WriteBuf>(&self, buf: &mut B) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += buf.put_u8(self.tag)?;
        w += self.service_error.put(buf)?;
        Ok(w)
    }
}

impl<'a> ImplicitTagged<'a> for ConfirmedServiceError {
    const TAG: u8 = 14;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(ConfirmedServiceError {
            tag: buf.get_u8()?,
            service_error: SnServiceError::get(buf)?,
        })
    }
}

/// Minimum supported DLMS version (the default value for
/// `Initiate-Request` / `Initiate-Response`).
pub const DLMS_VERSION_NUMBER: u8 = 6;

/// VAA-name reported in `Initiate-Response` (LN referencing, no ciphering).
pub const VAA_NAME_LN: ObjectName = ObjectName(0x0007);

/// `InitiateRequest ::= SEQUENCE` (`[1] IMPLICIT` in the xDLMS-APDU CHOICE).
///
/// `proposed-quality-of-service` is unused in DLMS and therefore not stored
/// in the struct; on the wire the field is still handled (see `put`/`decode`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InitiateRequest<'a> {
    pub dedicated_key: Option<&'a [u8]>,
    pub response_allowed: bool,
    pub proposed_dlms_version_number: u8,
    pub proposed_conformance: Conformance,
    pub client_max_receive_pdu_size: u16,
}

impl<'a> InitiateRequest<'a> {
    pub fn new(proposed_conformance: Conformance, client_max_receive_pdu_size: u16) -> Self {
        InitiateRequest {
            dedicated_key: None,
            response_allowed: true,
            proposed_dlms_version_number: DLMS_VERSION_NUMBER,
            proposed_conformance,
            client_max_receive_pdu_size,
        }
    }

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
        // proposed-quality-of-service: unused in DLMS — always absent.
        w += put_presence(buf, false)?;
        w += buf.put_u8(self.proposed_dlms_version_number)?;
        w += self.proposed_conformance.put(buf)?;
        w += buf.write(&self.client_max_receive_pdu_size.to_be_bytes())?;
        Ok(w)
    }
}

impl<'a> ImplicitTagged<'a> for InitiateRequest<'a> {
    const TAG: u8 = 1;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
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
        // proposed-quality-of-service: unused in DLMS — read and discard.
        if get_presence(buf)? {
            let _ = buf.get_u8()?;
        }
        Ok(InitiateRequest {
            dedicated_key,
            response_allowed,
            proposed_dlms_version_number: buf.get_u8()?,
            proposed_conformance: Conformance::get(buf)?,
            client_max_receive_pdu_size: get_u16(buf)?,
        })
    }
}

/// `InitiateResponse ::= SEQUENCE` (`[8] IMPLICIT` in the xDLMS-APDU CHOICE).
///
/// `negotiated-quality-of-service` is unused in DLMS and therefore not stored
/// in the struct; on the wire the field is still handled (see `put`/`decode`).
/// `vaa-name` is also fixed ([`VAA_NAME_LN`]) and not stored.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InitiateResponse {
    pub negotiated_dlms_version_number: u8,
    pub negotiated_conformance: Conformance,
    pub server_max_receive_pdu_size: u16,
}

impl InitiateResponse {
    pub fn new(negotiated_conformance: Conformance, server_max_receive_pdu_size: u16) -> Self {
        InitiateResponse {
            negotiated_dlms_version_number: DLMS_VERSION_NUMBER,
            negotiated_conformance,
            server_max_receive_pdu_size,
        }
    }

    pub fn put<B: WriteBuf>(&self, buf: &mut B) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        // negotiated-quality-of-service: unused in DLMS — always absent.
        w += put_presence(buf, false)?;
        w += buf.put_u8(self.negotiated_dlms_version_number)?;
        w += self.negotiated_conformance.put(buf)?;
        w += buf.write(&self.server_max_receive_pdu_size.to_be_bytes())?;
        // vaa-name: fixed (VAA_NAME_LN).
        w += VAA_NAME_LN.put(buf)?;
        Ok(w)
    }
}

impl<'a> ImplicitTagged<'a> for InitiateResponse {
    const TAG: u8 = 8;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        // negotiated-quality-of-service: unused in DLMS — read and discard.
        if get_presence(buf)? {
            let _ = buf.get_u8()?;
        }
        let negotiated_dlms_version_number = buf.get_u8()?;
        let negotiated_conformance = Conformance::get(buf)?;
        let server_max_receive_pdu_size = get_u16(buf)?;
        // vaa-name: fixed (VAA_NAME_LN) — read and discard.
        let _ = ObjectName::get(buf)?;
        Ok(InitiateResponse {
            negotiated_dlms_version_number,
            negotiated_conformance,
            server_max_receive_pdu_size,
        })
    }
}

/// `ReadRequest ::= SEQUENCE OF Variable-Access-Specification` (`[5] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadRequest<'a> {
    pub variable_access_specifications: VariableAccessSpecificationList<'a>,
}

impl<'a> ReadRequest<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_length(buf, self.variable_access_specifications.len())?;
        for item in self.variable_access_specifications {
            w += item?.put(buf)?;
        }
        Ok(w)
    }
}

impl<'a> ImplicitTagged<'a> for ReadRequest<'a> {
    const TAG: u8 = 5;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(ReadRequest {
            variable_access_specifications: VariableAccessSpecificationList::read(buf)?,
        })
    }
}

/// `ReadResponse ::= SEQUENCE OF CHOICE` (`[12] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadResponse<'a> {
    pub results: ReadResponseItemList<'a>,
}

impl<'a> ReadResponse<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_length(buf, self.results.len())?;
        for item in self.results {
            w += item?.put(buf)?;
        }
        Ok(w)
    }
}

impl<'a> ImplicitTagged<'a> for ReadResponse<'a> {
    const TAG: u8 = 12;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(ReadResponse {
            results: ReadResponseItemList::read(buf)?,
        })
    }
}

/// `WriteRequest ::= SEQUENCE` (`[6] IMPLICIT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WriteRequest<'a> {
    pub variable_access_specifications: VariableAccessSpecificationList<'a>,
    pub list_of_data: ReaderList<'a>,
}

impl<'a> WriteRequest<'a> {
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
}

impl<'a> ImplicitTagged<'a> for WriteRequest<'a> {
    const TAG: u8 = 6;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
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
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += put_length(buf, self.results.len())?;
        for item in self.results {
            w += item?.put(buf)?;
        }
        Ok(w)
    }
}

impl<'a> ImplicitTagged<'a> for WriteResponse<'a> {
    const TAG: u8 = 13;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(WriteResponse {
            results: WriteResponseItemList::read(buf)?,
        })
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
        Ok(NotificationBody {
            data_value: data_value(buf)?,
        })
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
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += self.long_invoke_id_and_priority.put(buf)?;
        w += crate::axdr::put_octet_string(buf, self.date_time)?;
        w += self.notification_body.put(buf)?;
        Ok(w)
    }
}

impl<'a> ImplicitTagged<'a> for DataNotification<'a> {
    const TAG: u8 = 15;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
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
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut w = buf.put_u8(Self::TAG)?;
        w += self.long_invoke_id_and_priority.put(buf)?;
        w += crate::axdr::put_octet_string(buf, self.date_time)?;
        Ok(w)
    }
}

impl<'a> ImplicitTagged<'a> for DataNotificationConfirm<'a> {
    const TAG: u8 = 16;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
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
}

impl<'a> ImplicitTagged<'a> for UnconfirmedWriteRequest<'a> {
    const TAG: u8 = 22;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
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
}

impl<'a> ImplicitTagged<'a> for InformationReportRequest<'a> {
    const TAG: u8 = 24;

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
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

/// XDLMS-APDU ::= CHOICE. Models the LN referencing GET/SET/ACTION services plus
/// event notification.
#[derive(Debug, Clone, PartialEq)]
pub enum XDLMSApdu<'a> {
    InitiateRequest(InitiateRequest<'a>),
    ReadRequest(ReadRequest<'a>),
    WriteRequest(WriteRequest<'a>),
    InitiateResponse(InitiateResponse),
    ReadResponse(ReadResponse<'a>),
    WriteResponse(WriteResponse<'a>),
    ConfirmedServiceError(ConfirmedServiceError),
    DataNotification(DataNotification<'a>),
    DataNotificationConfirm(DataNotificationConfirm<'a>),
    UnconfirmedWriteRequest(UnconfirmedWriteRequest<'a>),
    InformationReportRequest(InformationReportRequest<'a>),
    GetRequest(GetRequest<'a>),
    GetResponse(GetResponse<'a>),
    SetRequest(SetRequest<'a>),
    SetResponse(SetResponse<'a>),
    ActionRequest(ActionRequest<'a>),
    ActionResponse(ActionResponse<'a>),
    EventNotificationRequest(EventNotificationRequest<'a>),
    ExceptionResponse(ExceptionResponse),
}

impl<'a> ImplicitTagged<'a> for XDLMSApdu<'a> {
    /// The xDLMS-APDU is a top-level CHOICE with no single outer tag: the
    /// leading byte is the service discriminator. This placeholder is never
    /// validated (`get` is overridden below).
    const TAG: u8 = 0;

    /// `get` skips tag validation (there is no outer tag) and dispatches on
    /// the leading service byte.
    fn get(buf: &mut Reader<'a>) -> Result<Self> {
        Self::decode(buf)
    }

    fn decode(buf: &mut Reader<'a>) -> Result<Self> {
        Ok(match buf.get_u8()? {
            InitiateRequest::TAG => XDLMSApdu::InitiateRequest(InitiateRequest::decode(buf)?),
            ReadRequest::TAG => XDLMSApdu::ReadRequest(ReadRequest::decode(buf)?),
            WriteRequest::TAG => XDLMSApdu::WriteRequest(WriteRequest::decode(buf)?),
            InitiateResponse::TAG => XDLMSApdu::InitiateResponse(InitiateResponse::decode(buf)?),
            ReadResponse::TAG => XDLMSApdu::ReadResponse(ReadResponse::decode(buf)?),
            WriteResponse::TAG => XDLMSApdu::WriteResponse(WriteResponse::decode(buf)?),
            ConfirmedServiceError::TAG => {
                XDLMSApdu::ConfirmedServiceError(ConfirmedServiceError::decode(buf)?)
            }
            DataNotification::TAG => XDLMSApdu::DataNotification(DataNotification::decode(buf)?),
            DataNotificationConfirm::TAG => {
                XDLMSApdu::DataNotificationConfirm(DataNotificationConfirm::decode(buf)?)
            }
            UnconfirmedWriteRequest::TAG => {
                XDLMSApdu::UnconfirmedWriteRequest(UnconfirmedWriteRequest::decode(buf)?)
            }
            InformationReportRequest::TAG => {
                XDLMSApdu::InformationReportRequest(InformationReportRequest::decode(buf)?)
            }
            GetRequest::TAG => XDLMSApdu::GetRequest(GetRequest::decode(buf)?),
            GetResponse::TAG => XDLMSApdu::GetResponse(GetResponse::decode(buf)?),
            SetRequest::TAG => XDLMSApdu::SetRequest(SetRequest::decode(buf)?),
            EventNotificationRequest::TAG => {
                XDLMSApdu::EventNotificationRequest(EventNotificationRequest::decode(buf)?)
            }
            ActionRequest::TAG => XDLMSApdu::ActionRequest(ActionRequest::decode(buf)?),
            SetResponse::TAG => XDLMSApdu::SetResponse(SetResponse::decode(buf)?),
            ActionResponse::TAG => XDLMSApdu::ActionResponse(ActionResponse::decode(buf)?),
            ExceptionResponse::TAG => XDLMSApdu::ExceptionResponse(ExceptionResponse::decode(buf)?),
            other => return Err(Error::UnknownTag { tag: other }),
        })
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
                GetRequest::Normal(GetRequestNormal {
                    invoke,
                    descriptor: desc,
                    access_selection: None,
                }) => {
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
        let sel = SelectiveAccessDescriptorWrite {
            access_selector: 1,
            access_parameters: &value,
        };
        roundtrip!(
            |buf| GetRequest::put_normal(
                InvokeIdAndPriority::from_bits(2, true, false),
                descriptor(),
                Some(sel),
                buf,
            ),
            GetRequest::get,
            |d| match d {
                GetRequest::Normal(GetRequestNormal {
                    access_selection: Some(s),
                    ..
                }) => {
                    assert_eq!(s.access_selector, 1);
                    assert_eq!(
                        s.access_parameters.as_bytes(),
                        enc(&TestCodec(Data::Unsigned(5))).as_slice()
                    );
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
                GetRequest::WithList(GetRequestWithList { descriptors, .. }) => {
                    assert_eq!(descriptors.len(), 2);
                }
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
                GetResponse::Normal(GetResponseNormal {
                    result: GetDataResult::Data(reader),
                    ..
                }) => {
                    assert_eq!(
                        reader.as_bytes(),
                        enc(&TestCodec(Data::Long64(123456789))).as_slice()
                    );
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
                XDLMSApdu::GetResponse(GetResponse::Normal(GetResponseNormal {
                    result: GetDataResult::DataAccessError(DataAccessResult::ObjectUnavailable),
                    ..
                })) => {}
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
                SetRequest::Normal(SetRequestNormal { value: v, .. }) => {
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
                SetRequest::WithFirstDatablock(SetRequestWithFirstDatablock {
                    datablock: db,
                    ..
                }) => {
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
                SetRequest::WithList(SetRequestWithList { mut values, .. }) => {
                    assert_eq!(values.len(), 2);
                    assert_eq!(
                        values.next().unwrap().unwrap().as_bytes(),
                        enc(&TestCodec(Data::Unsigned(1))).as_slice()
                    );
                    assert_eq!(
                        values.next().unwrap().unwrap().as_bytes(),
                        enc(&TestCodec(Data::Unsigned(2))).as_slice()
                    );
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
                SetResponse::Normal(SetResponseNormal {
                    result: DataAccessResult::Success,
                    ..
                }) => {}
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
                SetResponse::WithList(SetResponseWithList { results, .. }) => {
                    assert_eq!(results.len(), 2);
                }
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
                ActionRequest::Normal(ActionRequestNormal {
                    method_invocation_parameters: Some(p),
                    ..
                }) => {
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
                ActionRequest::WithList(ActionRequestWithList {
                    method_invocation_parameters,
                    ..
                }) => {
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
                ActionResponseWithOptionalDataWrite {
                    result: 0,
                    return_parameters: None
                },
                buf,
            ),
            ActionResponse::get,
            |d| match d {
                ActionResponse::Normal(ActionResponseNormal {
                    single_response, ..
                }) => {
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
                assert_eq!(
                    d.time,
                    Some(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c".as_slice())
                );
                assert_eq!(
                    d.attribute_value.as_bytes(),
                    enc(&TestCodec(Data::Unsigned(1))).as_slice()
                );
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
                XDLMSApdu::SetRequest(SetRequest::Normal(SetRequestNormal {
                    value: v, ..
                })) => {
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
            service_error: ServiceError_::InvocationCounterError(42),
        };
        roundtrip!(
            |buf| resp.put(buf),
            ExceptionResponse::get,
            |d: ExceptionResponse| {
                assert_eq!(d.state_error, StateError::ServiceNotAllowed);
                assert_eq!(d.service_error, ServiceError_::InvocationCounterError(42));
            }
        );
    }

    #[test]
    fn xdlms_apdu_exception_response_dispatch_roundtrip() {
        let resp = ExceptionResponse {
            state_error: StateError::ServiceUnknown,
            service_error: ServiceError_::PduTooLong,
        };
        roundtrip!(|buf| resp.put(buf), XDLMSApdu::get, |d| match d {
            XDLMSApdu::ExceptionResponse(r) => {
                assert_eq!(r.state_error, StateError::ServiceUnknown);
                assert_eq!(r.service_error, ServiceError_::PduTooLong);
            }
            _ => panic!("wrong variant"),
        });
    }
}

#[cfg(test)]
mod sn_tests {
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
        let req = InitiateRequest::new(Conformance([0x1C, 0x03, 0x20]), 1200);
        let bytes = enc(|b| req.put(b));
        // Green Book Table 116 (SN referencing): 01 00 00 00 06 5F 1F 04 00 1C 03 20 04 B0
        assert_eq!(
            bytes,
            [0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x1C, 0x03, 0x20, 0x04, 0xB0]
        );

        let mut r = Reader::new(&bytes);
        let decoded = InitiateRequest::get(&mut r).unwrap();
        assert_eq!(decoded.proposed_dlms_version_number, 6);
        assert_eq!(
            decoded.proposed_conformance,
            Conformance([0x1C, 0x03, 0x20])
        );
        assert_eq!(decoded.client_max_receive_pdu_size, 1200);
        assert!(decoded.response_allowed);
        assert!(decoded.dedicated_key.is_none());
    }

    #[test]
    fn initiate_response_matches_green_book_example() {
        let resp = InitiateResponse::new(Conformance([0x1C, 0x03, 0x20]), 500);
        let bytes = enc(|b| resp.put(b));
        // Green Book Table 117 (vaa-name = VAA_NAME_LN = 0x0007): 08 00 06 5F 1F 04 00 1C 03 20 01 F4 00 07
        assert_eq!(
            bytes,
            [0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x1C, 0x03, 0x20, 0x01, 0xF4, 0x00, 0x07]
        );

        let mut r = Reader::new(&bytes);
        let decoded = InitiateResponse::get(&mut r).unwrap();
        assert_eq!(decoded.server_max_receive_pdu_size, 500);
    }

    #[test]
    fn conformance_bits_roundtrip() {
        let conf = Conformance::from_bits(ConformanceBits {
            read: true,
            write: true,
            unconfirmed_write: true,
            multiple_references: true,
            information_report: true,
            parameterized_access: true,
            ..ConformanceBits::default()
        });
        assert_eq!(conf, Conformance([0x1C, 0x03, 0x20]));
        assert!(conf.is_read());
        assert!(conf.is_write());
        assert!(conf.is_unconfirmed_write());
        assert!(conf.is_multiple_references());
        assert!(conf.is_information_report());
        assert!(conf.is_parameterized_access());
        assert!(!conf.is_get());
        assert!(!conf.is_action());
        assert!(!conf.is_general_protection());
    }

    #[test]
    fn confirmed_service_error_matches_green_book_example() {
        let err = ConfirmedServiceError {
            tag: confirmed_service_error_tag::INITIATE_ERROR,
            service_error: SnServiceError::Initiate(Initiate::DlmsVersionTooLow),
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
        assert_eq!(
            it.next().unwrap().unwrap(),
            ReadResponseItem::Data(Reader::new(&[0x11, 0x01]))
        );
        assert_eq!(
            it.next().unwrap().unwrap(),
            ReadResponseItem::DataAccessError(DataAccessResult::ReadWriteDenied)
        );
        assert_eq!(enc(|b| resp.put(b)), resp_bytes);
    }
}
