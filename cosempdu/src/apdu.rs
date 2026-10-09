//! xDLMS APDU types with A-XDR encoding (IEC 61334-6).
//!
//! Mirrors the confirmed GET/SET/ACTION request-response services from
//! `src/COSEMpdu/apdu.py` (Green Book 8.3). The complete xDLMS APDU is a large
//! CHOICE; this module implements the most commonly used services plus the
//! [`XDLMSApdu`] dispatch type.

use crate::axdr::{get_length, put_length};
use bytebuffer::{ByteBuffer, Reader};
use crate::data::{decode_data, Arena, Data};
use crate::error::{Error, Result};

/// Bundles the arenas needed to decode an APDU and its nested `Data` values.
pub struct DecodeContext<'a> {
    pub data: Arena<'a, Data<'a>>,
    pub get_data_result: Arena<'a, GetDataResult<'a>>,
    pub descriptors: Arena<'a, (CosemAttributeDescriptor, Option<SelectiveAccessDescriptor<'a>>)>,
    pub method_descriptors: Arena<'a, CosemMethodDescriptor>,
    pub action_response: Arena<'a, ActionResponseWithOptionalData<'a>>,
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
    pub access_parameters: Data<'a>,
}

impl<'a> SelectiveAccessDescriptor<'a> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(self.access_selector)?;
        written += self.access_parameters.put(buf)?;
        Ok(written)
    }

    fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        let access_selector = buf.get_u8()?;
        let access_parameters = Data::get(buf, &mut ctx.data)?;
        Ok(SelectiveAccessDescriptor {
            access_selector,
            access_parameters,
        })
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
        descriptors: &'a [(CosemAttributeDescriptor, Option<SelectiveAccessDescriptor<'a>>)],
    },
}

impl<'a> GetRequest<'a> {
    const TAG: u8 = 192;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += self.put_lc(buf)?;
        Ok(written)
    }


    fn put_lc(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            GetRequest::Normal {
                invoke,
                descriptor,
                access_selection,
            } => {
                let mut written = buf.put_u8(1)?;
                written += invoke.put(buf)?;
                written += descriptor.put(buf)?;
                written += put_presence(buf, access_selection.is_some())?;
                if let Some(sel) = access_selection {
                    written += sel.put(buf)?;
                }
                Ok(written)
            }
            GetRequest::Next { invoke, block_number } => {
                let mut written = buf.put_u8(2)?;
                written += invoke.put(buf)?;
                written += buf.write(&block_number.to_be_bytes())?;
                Ok(written)
            }
            GetRequest::WithList { invoke, descriptors } => {
                let mut written = buf.put_u8(3)?;
                written += invoke.put(buf)?;
                written += put_length(buf, descriptors.len())?;
                for (desc, sel) in *descriptors {
                    written += desc.put(buf)?;
                    written += put_presence(buf, sel.is_some())?;
                    if let Some(s) = sel {
                        written += s.put(buf)?;
                    }
                }
                Ok(written)
            }
        }
    }

    pub fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Get-Request [192]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptor = CosemAttributeDescriptor::get(buf)?;
                let access_selection = if get_presence(buf)? {
                    Some(SelectiveAccessDescriptor::get(buf, ctx)?)
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
                let n = get_length(buf)?;
                let slice = ctx.descriptors.alloc(n)?;
                let ptr = slice.as_mut_ptr() as *mut (CosemAttributeDescriptor, Option<SelectiveAccessDescriptor<'a>>);
                for i in 0..n {
                    let descriptor = CosemAttributeDescriptor::get(buf)?;
                    let sel = if get_presence(buf)? {
                        Some(SelectiveAccessDescriptor::get(buf, ctx)?)
                    } else {
                        None
                    };
                    unsafe { ptr.add(i).write((descriptor, sel)) };
                }
                let descriptors = unsafe { core::slice::from_raw_parts(ptr, n) };
                GetRequest::WithList { invoke, descriptors }
            }
            other => return Err(Error::UnknownChoice { name: "Get-Request", choice: other }),
        })
    }
}

/// Get-Data-Result ::= CHOICE { data [0], data-access-error [1] }.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GetDataResult<'a> {
    Data(Data<'a>),
    DataAccessError(u8),
}

impl<'a> GetDataResult<'a> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            GetDataResult::Data(d) => {
                let mut written = buf.put_u8(0)?;
                written += d.put(buf)?;
                Ok(written)
            }
            GetDataResult::DataAccessError(code) => {
                let mut written = buf.put_u8(1)?;
                written += buf.put_u8(*code)?;
                Ok(written)
            }
        }
    }

    fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        match buf.get_u8()? {
            0 => Ok(GetDataResult::Data(Data::get(buf, &mut ctx.data)?)),
            1 => Ok(GetDataResult::DataAccessError(buf.get_u8()?)),
            t => Err(Error::UnknownChoice { name: "Get-Data-Result", choice: t }),
        }
    }
}

/// DataBlock-G.result ::= CHOICE { raw-data [0], data-access-result [1] }.
#[derive(Debug, Clone, PartialEq)]
pub enum DataBlockGResult<'a> {
    RawData(&'a [u8]),
    DataAccessError(u8),
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
                written += buf.put_u8(*code)?;
                Ok(written)
            }
        }
    }

    fn get(buf: &mut Reader<'a>, _ctx: &mut DecodeContext<'a>) -> Result<Self> {
        match buf.get_u8()? {
            0 => Ok(DataBlockGResult::RawData(crate::axdr::get_octet_string(buf)?)),
            1 => Ok(DataBlockGResult::DataAccessError(buf.get_u8()?)),
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

    fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        Ok(DataBlockG {
            last_block: get_presence(buf)?,
            block_number: u32::from_be_bytes(read_n::<4>(buf)?),
            result: DataBlockGResult::get(buf, ctx)?,
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

    fn get(buf: &mut Reader<'a>, _ctx: &mut DecodeContext<'a>) -> Result<Self> {
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
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(self.result)?;
        written += put_presence(buf, self.return_parameters.is_some())?;
        if let Some(rp) = &self.return_parameters {
            written += rp.put(buf)?;
        }
        Ok(written)
    }

    fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        let result = buf.get_u8()?;
        let return_parameters = if get_presence(buf)? {
            Some(GetDataResult::get(buf, ctx)?)
        } else {
            None
        };
        Ok(ActionResponseWithOptionalData {
            result,
            return_parameters,
        })
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
        results: &'a [GetDataResult<'a>],
    },
}

impl<'a> GetResponse<'a> {
    const TAG: u8 = 196;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += self.put_lc(buf)?;
        Ok(written)
    }


    fn put_lc(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            GetResponse::Normal { invoke, result } => {
                let mut written = buf.put_u8(1)?;
                written += invoke.put(buf)?;
                written += result.put(buf)?;
                Ok(written)
            }
            GetResponse::WithDatablock { invoke, result } => {
                let mut written = buf.put_u8(2)?;
                written += invoke.put(buf)?;
                written += result.put(buf)?;
                Ok(written)
            }
            GetResponse::WithList { invoke, results } => {
                let mut written = buf.put_u8(3)?;
                written += invoke.put(buf)?;
                written += put_length(buf, results.len())?;
                for r in *results {
                    written += r.put(buf)?;
                }
                Ok(written)
            }
        }
    }

    pub fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Get-Response [196]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let result = GetDataResult::get(buf, ctx)?;
                GetResponse::Normal { invoke, result }
            }
            2 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let result = DataBlockG::get(buf, ctx)?;
                GetResponse::WithDatablock { invoke, result }
            }
            3 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let n = get_length(buf)?;
                let slice = ctx.get_data_result.alloc(n)?;
                let ptr = slice.as_mut_ptr() as *mut GetDataResult<'a>;
                for i in 0..n {
                    unsafe { ptr.add(i).write(GetDataResult::get(buf, ctx)?) };
                }
                let results = unsafe { core::slice::from_raw_parts(ptr, n) };
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
        value: Data<'a>,
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
        descriptors: &'a [(CosemAttributeDescriptor, Option<SelectiveAccessDescriptor<'a>>)],
        values: &'a [Data<'a>],
    },
    WithListAndFirstDatablock {
        invoke: InvokeIdAndPriority,
        descriptors: &'a [(CosemAttributeDescriptor, Option<SelectiveAccessDescriptor<'a>>)],
        datablock: DataBlockSA<'a>,
    },
}

impl<'a> SetRequest<'a> {
    const TAG: u8 = 193;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += self.put_lc(buf)?;
        Ok(written)
    }


    fn put_lc(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            SetRequest::Normal {
                invoke,
                descriptor,
                access_selection,
                value,
            } => {
                let mut written = buf.put_u8(1)?;
                written += invoke.put(buf)?;
                written += descriptor.put(buf)?;
                written += put_presence(buf, access_selection.is_some())?;
                if let Some(sel) = access_selection {
                    written += sel.put(buf)?;
                }
                written += value.put(buf)?;
                Ok(written)
            }
            SetRequest::WithFirstDatablock {
                invoke,
                descriptor,
                access_selection,
                datablock,
            } => {
                let mut written = buf.put_u8(2)?;
                written += invoke.put(buf)?;
                written += descriptor.put(buf)?;
                written += put_presence(buf, access_selection.is_some())?;
                if let Some(sel) = access_selection {
                    written += sel.put(buf)?;
                }
                written += datablock.put(buf)?;
                Ok(written)
            }
            SetRequest::WithDatablock {
                invoke,
                descriptor,
                access_selection,
                datablock,
            } => {
                let mut written = buf.put_u8(3)?;
                written += invoke.put(buf)?;
                written += descriptor.put(buf)?;
                written += put_presence(buf, access_selection.is_some())?;
                if let Some(sel) = access_selection {
                    written += sel.put(buf)?;
                }
                written += datablock.put(buf)?;
                Ok(written)
            }
            SetRequest::WithList {
                invoke,
                descriptors,
                values,
            } => {
                let mut written = buf.put_u8(4)?;
                written += invoke.put(buf)?;
                written += put_length(buf, descriptors.len())?;
                for (desc, sel) in *descriptors {
                    written += desc.put(buf)?;
                    written += put_presence(buf, sel.is_some())?;
                    if let Some(s) = sel {
                        written += s.put(buf)?;
                    }
                }
                written += put_length(buf, values.len())?;
                for v in *values {
                    written += v.put(buf)?;
                }
                Ok(written)
            }
            SetRequest::WithListAndFirstDatablock {
                invoke,
                descriptors,
                datablock,
            } => {
                let mut written = buf.put_u8(5)?;
                written += invoke.put(buf)?;
                written += put_length(buf, descriptors.len())?;
                for (desc, sel) in *descriptors {
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
    }

    pub fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Set-Request [193]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptor = CosemAttributeDescriptor::get(buf)?;
                let access_selection = if get_presence(buf)? {
                    Some(SelectiveAccessDescriptor::get(buf, ctx)?)
                } else {
                    None
                };
                let value = Data::get(buf, &mut ctx.data)?;
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
                    Some(SelectiveAccessDescriptor::get(buf, ctx)?)
                } else {
                    None
                };
                let datablock = DataBlockSA::get(buf, ctx)?;
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
                    Some(SelectiveAccessDescriptor::get(buf, ctx)?)
                } else {
                    None
                };
                let datablock = DataBlockSA::get(buf, ctx)?;
                SetRequest::WithDatablock {
                    invoke,
                    descriptor,
                    access_selection,
                    datablock,
                }
            }
            4 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let n = get_length(buf)?;
                let slice = ctx.descriptors.alloc(n)?;
                let ptr = slice.as_mut_ptr() as *mut (CosemAttributeDescriptor, Option<SelectiveAccessDescriptor<'a>>);
                for i in 0..n {
                    let descriptor = CosemAttributeDescriptor::get(buf)?;
                    let sel = if get_presence(buf)? {
                        Some(SelectiveAccessDescriptor::get(buf, ctx)?)
                    } else {
                        None
                    };
                    unsafe { ptr.add(i).write((descriptor, sel)) };
                }
                let descriptors = unsafe { core::slice::from_raw_parts(ptr, n) };
                let n = get_length(buf)?;
                let values = decode_data(buf, &mut ctx.data, n)?;
                SetRequest::WithList {
                    invoke,
                    descriptors,
                    values,
                }
            }
            5 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let n = get_length(buf)?;
                let slice = ctx.descriptors.alloc(n)?;
                let ptr = slice.as_mut_ptr() as *mut (CosemAttributeDescriptor, Option<SelectiveAccessDescriptor<'a>>);
                for i in 0..n {
                    let descriptor = CosemAttributeDescriptor::get(buf)?;
                    let sel = if get_presence(buf)? {
                        Some(SelectiveAccessDescriptor::get(buf, ctx)?)
                    } else {
                        None
                    };
                    unsafe { ptr.add(i).write((descriptor, sel)) };
                }
                let descriptors = unsafe { core::slice::from_raw_parts(ptr, n) };
                let datablock = DataBlockSA::get(buf, ctx)?;
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

/// Set-Response ::= [197] IMPLICIT CHOICE.
#[derive(Debug, Clone, PartialEq)]
pub enum SetResponse<'a> {
    Normal {
        invoke: InvokeIdAndPriority,
        result: GetDataResult<'a>,
    },
    Datablock {
        invoke: InvokeIdAndPriority,
        block_number: u32,
    },
    LastDatablock {
        invoke: InvokeIdAndPriority,
        result: u8,
        block_number: u32,
    },
    LastDatablockWithList {
        invoke: InvokeIdAndPriority,
        results: &'a [u8],
        block_number: u32,
    },
    WithList {
        invoke: InvokeIdAndPriority,
        results: &'a [u8],
    },
}

impl<'a> SetResponse<'a> {
    const TAG: u8 = 197;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += self.put_lc(buf)?;
        Ok(written)
    }


    fn put_lc(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            SetResponse::Normal { invoke, result } => {
                let mut written = buf.put_u8(1)?;
                written += invoke.put(buf)?;
                written += result.put(buf)?;
                Ok(written)
            }
            SetResponse::Datablock {
                invoke,
                block_number,
            } => {
                let mut written = buf.put_u8(2)?;
                written += invoke.put(buf)?;
                written += buf.write(&block_number.to_be_bytes())?;
                Ok(written)
            }
            SetResponse::LastDatablock {
                invoke,
                result,
                block_number,
            } => {
                let mut written = buf.put_u8(3)?;
                written += invoke.put(buf)?;
                written += buf.put_u8(*result)?;
                written += buf.write(&block_number.to_be_bytes())?;
                Ok(written)
            }
            SetResponse::LastDatablockWithList {
                invoke,
                results,
                block_number,
            } => {
                let mut written = buf.put_u8(4)?;
                written += invoke.put(buf)?;
                written += put_length(buf, results.len())?;
                written += buf.write(*results)?;
                written += buf.write(&block_number.to_be_bytes())?;
                Ok(written)
            }
            SetResponse::WithList { invoke, results } => {
                let mut written = buf.put_u8(5)?;
                written += invoke.put(buf)?;
                written += put_length(buf, results.len())?;
                written += buf.write(*results)?;
                Ok(written)
            }
        }
    }

    pub fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Set-Response [197]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let result = GetDataResult::get(buf, ctx)?;
                SetResponse::Normal { invoke, result }
            }
            2 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
                SetResponse::Datablock {
                    invoke,
                    block_number,
                }
            }
            3 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let result = buf.get_u8()?;
                let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
                SetResponse::LastDatablock {
                    invoke,
                    result,
                    block_number,
                }
            }
            4 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let n = get_length(buf)?;
                let results = buf.read(n)?;
                let block_number = u32::from_be_bytes(read_n::<4>(buf)?);
                SetResponse::LastDatablockWithList {
                    invoke,
                    results,
                    block_number,
                }
            }
            5 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let n = get_length(buf)?;
                let results = buf.read(n)?;
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
        method_invocation_parameters: Option<Data<'a>>,
    },
    NextPblock {
        invoke: InvokeIdAndPriority,
        block_number: u32,
    },
    WithList {
        invoke: InvokeIdAndPriority,
        descriptors: &'a [CosemMethodDescriptor],
        method_invocation_parameters: &'a [Data<'a>],
    },
    WithFirstPblock {
        invoke: InvokeIdAndPriority,
        descriptor: CosemMethodDescriptor,
        pblock: DataBlockSA<'a>,
    },
    WithListAndFirstPblock {
        invoke: InvokeIdAndPriority,
        descriptors: &'a [CosemMethodDescriptor],
        pblock: DataBlockSA<'a>,
    },
    WithPblock {
        invoke: InvokeIdAndPriority,
        pblock: DataBlockSA<'a>,
    },
}

impl<'a> ActionRequest<'a> {
    const TAG: u8 = 195;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += self.put_lc(buf)?;
        Ok(written)
    }


    fn put_lc(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            ActionRequest::Normal {
                invoke,
                descriptor,
                method_invocation_parameters,
            } => {
                let mut written = buf.put_u8(1)?;
                written += invoke.put(buf)?;
                written += descriptor.put(buf)?;
                written += put_presence(buf, method_invocation_parameters.is_some())?;
                if let Some(d) = method_invocation_parameters {
                    written += d.put(buf)?;
                }
                Ok(written)
            }
            ActionRequest::NextPblock {
                invoke,
                block_number,
            } => {
                let mut written = buf.put_u8(2)?;
                written += invoke.put(buf)?;
                written += buf.write(&block_number.to_be_bytes())?;
                Ok(written)
            }
            ActionRequest::WithList {
                invoke,
                descriptors,
                method_invocation_parameters,
            } => {
                let mut written = buf.put_u8(3)?;
                written += invoke.put(buf)?;
                written += put_length(buf, descriptors.len())?;
                for desc in *descriptors {
                    written += desc.put(buf)?;
                }
                written += put_length(buf, method_invocation_parameters.len())?;
                for d in *method_invocation_parameters {
                    written += d.put(buf)?;
                }
                Ok(written)
            }
            ActionRequest::WithFirstPblock {
                invoke,
                descriptor,
                pblock,
            } => {
                let mut written = buf.put_u8(4)?;
                written += invoke.put(buf)?;
                written += descriptor.put(buf)?;
                written += pblock.put(buf)?;
                Ok(written)
            }
            ActionRequest::WithListAndFirstPblock {
                invoke,
                descriptors,
                pblock,
            } => {
                let mut written = buf.put_u8(5)?;
                written += invoke.put(buf)?;
                written += put_length(buf, descriptors.len())?;
                for desc in *descriptors {
                    written += desc.put(buf)?;
                }
                written += pblock.put(buf)?;
                Ok(written)
            }
            ActionRequest::WithPblock { invoke, pblock } => {
                let mut written = buf.put_u8(6)?;
                written += invoke.put(buf)?;
                written += pblock.put(buf)?;
                Ok(written)
            }
        }
    }

    pub fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Action-Request [195]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptor = CosemMethodDescriptor::get(buf)?;
                let method_invocation_parameters = if get_presence(buf)? {
                    Some(Data::get(buf, &mut ctx.data)?)
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
                let n = get_length(buf)?;
                let slice = ctx.method_descriptors.alloc(n)?;
                let ptr = slice.as_mut_ptr() as *mut CosemMethodDescriptor;
                for i in 0..n {
                    unsafe { ptr.add(i).write(CosemMethodDescriptor::get(buf)?) };
                }
                let descriptors = unsafe { core::slice::from_raw_parts(ptr, n) };
                let n = get_length(buf)?;
                let method_invocation_parameters = decode_data(buf, &mut ctx.data, n)?;
                ActionRequest::WithList {
                    invoke,
                    descriptors,
                    method_invocation_parameters,
                }
            }
            4 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let descriptor = CosemMethodDescriptor::get(buf)?;
                let pblock = DataBlockSA::get(buf, ctx)?;
                ActionRequest::WithFirstPblock {
                    invoke,
                    descriptor,
                    pblock,
                }
            }
            5 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let n = get_length(buf)?;
                let slice = ctx.method_descriptors.alloc(n)?;
                let ptr = slice.as_mut_ptr() as *mut CosemMethodDescriptor;
                for i in 0..n {
                    unsafe { ptr.add(i).write(CosemMethodDescriptor::get(buf)?) };
                }
                let descriptors = unsafe { core::slice::from_raw_parts(ptr, n) };
                let pblock = DataBlockSA::get(buf, ctx)?;
                ActionRequest::WithListAndFirstPblock {
                    invoke,
                    descriptors,
                    pblock,
                }
            }
            6 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let pblock = DataBlockSA::get(buf, ctx)?;
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
        list_of_responses: &'a [ActionResponseWithOptionalData<'a>],
    },
    NextPblock {
        invoke: InvokeIdAndPriority,
        block_number: u32,
    },
}

impl<'a> ActionResponse<'a> {
    const TAG: u8 = 199;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += self.put_lc(buf)?;
        Ok(written)
    }


    fn put_lc(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            ActionResponse::Normal {
                invoke,
                single_response,
            } => {
                let mut written = buf.put_u8(1)?;
                written += invoke.put(buf)?;
                written += single_response.put(buf)?;
                Ok(written)
            }
            ActionResponse::WithPblock { invoke, pblock } => {
                let mut written = buf.put_u8(2)?;
                written += invoke.put(buf)?;
                written += pblock.put(buf)?;
                Ok(written)
            }
            ActionResponse::WithList {
                invoke,
                list_of_responses,
            } => {
                let mut written = buf.put_u8(3)?;
                written += invoke.put(buf)?;
                written += put_length(buf, list_of_responses.len())?;
                for r in *list_of_responses {
                    written += r.put(buf)?;
                }
                Ok(written)
            }
            ActionResponse::NextPblock {
                invoke,
                block_number,
            } => {
                let mut written = buf.put_u8(4)?;
                written += invoke.put(buf)?;
                written += buf.write(&block_number.to_be_bytes())?;
                Ok(written)
            }
        }
    }

    pub fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        let tag = buf.get_u8()?;
        if tag != Self::TAG {
            return Err(Error::UnexpectedTag { name: "Action-Response [199]", actual: tag });
        }
        Ok(match buf.get_u8()? {
            1 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let single_response = ActionResponseWithOptionalData::get(buf, ctx)?;
                ActionResponse::Normal {
                    invoke,
                    single_response,
                }
            }
            2 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let pblock = DataBlockSA::get(buf, ctx)?;
                ActionResponse::WithPblock { invoke, pblock }
            }
            3 => {
                let invoke = InvokeIdAndPriority::get(buf)?;
                let n = get_length(buf)?;
                let slice = ctx.action_response.alloc(n)?;
                let ptr = slice.as_mut_ptr() as *mut ActionResponseWithOptionalData<'a>;
                for i in 0..n {
                    unsafe { ptr.add(i).write(ActionResponseWithOptionalData::get(buf, ctx)?) };
                }
                let list_of_responses = unsafe { core::slice::from_raw_parts(ptr, n) };
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
    pub attribute_value: Data<'a>,
}

impl<'a> EventNotificationRequest<'a> {
    const TAG: u8 = 194;

    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(Self::TAG)?;
        written += put_presence(buf, self.time.is_some())?;
        if let Some(t) = &self.time {
            written += crate::axdr::put_octet_string(buf, t)?;
        }
        written += self.descriptor.put(buf)?;
        written += self.attribute_value.put(buf)?;
        Ok(written)
    }


    pub fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
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
        let attribute_value = Data::get(buf, &mut ctx.data)?;
        Ok(EventNotificationRequest {
            time,
            descriptor,
            attribute_value,
        })
    }
}

/// XDLMS-APDU ::= CHOICE. Models the LN referencing GET/SET/ACTION services plus
/// event notification.
#[derive(Debug, Clone, PartialEq)]
pub enum XDLMSApdu<'a> {
    GetRequest(GetRequest<'a>),
    GetResponse(GetResponse<'a>),
    SetRequest(SetRequest<'a>),
    SetResponse(SetResponse<'a>),
    ActionRequest(ActionRequest<'a>),
    ActionResponse(ActionResponse<'a>),
    EventNotificationRequest(EventNotificationRequest<'a>),
}

impl<'a> XDLMSApdu<'a> {
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            XDLMSApdu::GetRequest(g) => g.put(buf),
            XDLMSApdu::GetResponse(g) => g.put(buf),
            XDLMSApdu::SetRequest(g) => g.put(buf),
            XDLMSApdu::SetResponse(g) => g.put(buf),
            XDLMSApdu::ActionRequest(g) => g.put(buf),
            XDLMSApdu::ActionResponse(g) => g.put(buf),
            XDLMSApdu::EventNotificationRequest(g) => g.put(buf),
        }
    }

    /// Decode from a buffer; detects the APDU by its leading tag byte.
    pub fn get(buf: &mut Reader<'a>, ctx: &mut DecodeContext<'a>) -> Result<Self> {
        match buf.peek(1)?.first().copied() {
            Some(GetRequest::TAG) => Ok(XDLMSApdu::GetRequest(GetRequest::get(buf, ctx)?)),
            Some(GetResponse::TAG) => Ok(XDLMSApdu::GetResponse(GetResponse::get(buf, ctx)?)),
            Some(SetRequest::TAG) => Ok(XDLMSApdu::SetRequest(SetRequest::get(buf, ctx)?)),
            Some(EventNotificationRequest::TAG) => Ok(XDLMSApdu::EventNotificationRequest(
                EventNotificationRequest::get(buf, ctx)?,
            )),
            Some(ActionRequest::TAG) => Ok(XDLMSApdu::ActionRequest(ActionRequest::get(buf, ctx)?)),
            Some(SetResponse::TAG) => Ok(XDLMSApdu::SetResponse(SetResponse::get(buf, ctx)?)),
            Some(ActionResponse::TAG) => Ok(XDLMSApdu::ActionResponse(ActionResponse::get(buf, ctx)?)),
            Some(t) => Err(Error::UnknownTag { name: "xDLMS-APDU", tag: t }),
            None => Err(Error::Message("empty xDLMS-APDU")),
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
            let mut data_storage = [core::mem::MaybeUninit::uninit(); 256];
            let mut gdr_storage = [core::mem::MaybeUninit::uninit(); 64];
            let mut desc_storage = [core::mem::MaybeUninit::uninit(); 64];
            let mut md_storage = [core::mem::MaybeUninit::uninit(); 64];
            let mut ar_storage = [core::mem::MaybeUninit::uninit(); 64];
            let mut ctx = DecodeContext {
                data: Arena::new(&mut data_storage),
                get_data_result: Arena::new(&mut gdr_storage),
                descriptors: Arena::new(&mut desc_storage),
                method_descriptors: Arena::new(&mut md_storage),
                action_response: Arena::new(&mut ar_storage),
            };
            let decoded = $get(&mut r, &mut ctx).unwrap();
            let mut backing2 = [0u8; 4096];
            let m = {
                let mut buf = ByteBuffer::new(&mut backing2);
                decoded.put(&mut buf).unwrap();
                buf.pos()
            };
            assert_eq!(&backing2[..m], &expected[..]);
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
        let req = GetRequest::Normal {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            descriptor: descriptor(),
            access_selection: None,
        };
        roundtrip!(req, GetRequest::get);
    }

    #[test]
    fn get_request_normal_with_selection_roundtrip() {
        let req = GetRequest::Normal {
            invoke: InvokeIdAndPriority::from_bits(2, true, false),
            descriptor: descriptor(),
            access_selection: Some(SelectiveAccessDescriptor {
                access_selector: 1,
                access_parameters: Data::Unsigned(5),
            }),
        };
        roundtrip!(req, GetRequest::get);
    }

    #[test]
    fn get_request_with_list_roundtrip() {
        let req = GetRequest::WithList {
            invoke: InvokeIdAndPriority::from_bits(3, true, false),
            descriptors: &[(descriptor(), None), (descriptor(), None)],
        };
        roundtrip!(req, GetRequest::get);
    }

    #[test]
    fn get_response_normal_roundtrip() {
        let resp = GetResponse::Normal {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            result: GetDataResult::Data(Data::Long64(123456789)),
        };
        roundtrip!(resp, GetResponse::get);
    }

    #[test]
    fn xdlms_apdu_dispatch_roundtrip() {
        let apdu = XDLMSApdu::GetResponse(GetResponse::Normal {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            result: GetDataResult::DataAccessError(11),
        });
        roundtrip!(apdu, XDLMSApdu::get);
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
        let req = SetRequest::Normal {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            descriptor: descriptor(),
            access_selection: None,
            value: Data::Unsigned(42),
        };
        roundtrip!(req, SetRequest::get);
    }

    #[test]
    fn set_request_with_first_datablock_roundtrip() {
        let req = SetRequest::WithFirstDatablock {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            descriptor: descriptor(),
            access_selection: None,
            datablock: DataBlockSA {
                last_block: false,
                block_number: 0,
                raw_data: b"\xDE\xAD",
            },
        };
        roundtrip!(req, SetRequest::get);
    }

    #[test]
    fn set_request_with_list_roundtrip() {
        let req = SetRequest::WithList {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            descriptors: &[(descriptor(), None), (descriptor(), None)],
            values: &[Data::Unsigned(1), Data::Unsigned(2)],
        };
        roundtrip!(req, SetRequest::get);
    }

    #[test]
    fn set_response_normal_roundtrip() {
        let resp = SetResponse::Normal {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            result: GetDataResult::DataAccessError(0),
        };
        roundtrip!(resp, SetResponse::get);
    }

    #[test]
    fn set_response_with_list_roundtrip() {
        let resp = SetResponse::WithList {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            results: &[0, 0],
        };
        roundtrip!(resp, SetResponse::get);
    }

    #[test]
    fn action_request_normal_roundtrip() {
        let req = ActionRequest::Normal {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            descriptor: method_descriptor(),
            method_invocation_parameters: Some(Data::Unsigned(7)),
        };
        roundtrip!(req, ActionRequest::get);
    }

    #[test]
    fn action_request_with_list_roundtrip() {
        let req = ActionRequest::WithList {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            descriptors: &[method_descriptor()],
            method_invocation_parameters: &[Data::Unsigned(1), Data::Unsigned(2)],
        };
        roundtrip!(req, ActionRequest::get);
    }

    #[test]
    fn action_response_normal_roundtrip() {
        let resp = ActionResponse::Normal {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            single_response: ActionResponseWithOptionalData {
                result: 0,
                return_parameters: None,
            },
        };
        roundtrip!(resp, ActionResponse::get);
    }

    #[test]
    fn event_notification_roundtrip() {
        let req = EventNotificationRequest {
            time: Some(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"),
            descriptor: descriptor(),
            attribute_value: Data::Unsigned(1),
        };
        roundtrip!(req, EventNotificationRequest::get);
    }

    #[test]
    fn xdlms_apdu_set_action_dispatch_roundtrip() {
        let apdu = XDLMSApdu::SetRequest(SetRequest::Normal {
            invoke: InvokeIdAndPriority::from_bits(1, true, false),
            descriptor: descriptor(),
            access_selection: None,
            value: Data::Unsigned(9),
        });
        roundtrip!(apdu, XDLMSApdu::get);
    }
}
