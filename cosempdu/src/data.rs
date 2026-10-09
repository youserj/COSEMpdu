//! DLMS/COSEM data types with A-XDR encoding (IEC 61334-6).
//!
//! Mirrors `src/COSEMpdu/data.py`: a single [`Data`] choice type carrying every
//! COSEM base data type. Each variant maps to the implicit tag number used by
//! A-XDR (IEC 61334-6 §6.6).

use crate::axdr::{
    get_bit_string, get_length, get_octet_string, get_string, put_bit_string,
    put_length, put_octet_string, put_string,
};
use bytebuffer::{ByteBuffer, Reader};
use crate::error::{Error, Result};

/// COSEM DLMS data value (`Data ::= CHOICE`).
///
/// Variable-length payloads (`OctetString`, `VisibleString`, `Utf8String`,
/// `BitString`, `CompactArray`) borrow their bytes from the input buffer for
/// its lifetime `'a`, enabling zero-copy decoding.
/// Bump allocator for zero-copy decoding of nested `Array`/`Structure`.
///
/// The arena is backed by a caller-provided slice of `MaybeUninit<Data<'a>>`.
/// It is self-referential: a decoded [`Data`] may contain `&'a [Data<'a>]`
/// references pointing back into this same arena, so slots can only be written
/// during a single decode pass and read afterwards. This is the one place the
/// library uses `unsafe`.
pub struct Arena<'a, T> {
    storage: &'a mut [core::mem::MaybeUninit<T>],
    len: usize,
}

impl<'a, T> Arena<'a, T> {
    /// Wrap a caller-provided backing slice for zero-copy decode.
    pub fn new(storage: &'a mut [core::mem::MaybeUninit<T>]) -> Self {
        Arena { storage, len: 0 }
    }

    /// Number of `Data` slots currently allocated.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no slots have been allocated yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn alloc(&mut self, n: usize) -> Result<&'a mut [core::mem::MaybeUninit<T>]> {
        if self.len + n > self.storage.len() {
            return Err(Error::Message("arena overflow"));
        }
        let start = self.len;
        self.len += n;
        let ptr = self.storage.as_mut_ptr();
        // SAFETY: `ptr.add(start)` points within `storage`, which lives for
        // `'a`; the sub-slice [start, start+n) is disjoint from any previously
        // handed out slice because `len` only ever advances.
        Ok(unsafe { core::slice::from_raw_parts_mut(ptr.add(start), n) })
    }

}

/// Decode `n` `Data` values from `buf` into `arena`, returning them as a
/// borrowed slice (zero-copy).
pub fn decode_data<'a>(
    buf: &mut Reader<'a>,
    arena: &mut Arena<'a, Data<'a>>,
    n: usize,
) -> Result<&'a [Data<'a>]> {
    let slice = arena.alloc(n)?;
    let ptr = slice.as_mut_ptr() as *mut Data<'a>;
    for i in 0..n {
        let item = Data::get(buf, arena)?;
        unsafe { ptr.add(i).write(item) };
    }
    Ok(unsafe { core::slice::from_raw_parts(ptr, n) })
}

/// COSEM DLMS data value (`Data ::= CHOICE`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Data<'a> {
    /// `null-data [0] IMPLICIT NULL`
    NullData,
    /// `array [1] IMPLICIT SEQUENCE OF Data`
    Array(&'a [Data<'a>]),
    /// `structure [2] IMPLICIT SEQUENCE OF Data`
    Structure(&'a [Data<'a>]),
    /// `boolean [3] IMPLICIT BOOLEAN`
    Boolean(bool),
    /// `bit-string [4] IMPLICIT BIT STRING` (packed octets + significant bit count)
    BitString { bytes: &'a [u8], bit_len: usize },
    /// `double-long [5] IMPLICIT Integer32`
    DoubleLong(i32),
    /// `double-long-unsigned [6] IMPLICIT Unsigned32`
    DoubleLongUnsigned(u32),
    /// `octet-string [9] IMPLICIT OCTET STRING`
    OctetString(&'a [u8]),
    /// `visible-string [10] IMPLICIT VisibleString`
    VisibleString(&'a str),
    /// `utf8-string [12] IMPLICIT UTF8String`
    Utf8String(&'a str),
    /// `bcd [13] IMPLICIT Integer8`
    Bcd(i8),
    /// `integer [15] IMPLICIT Integer8`
    Integer(i8),
    /// `long [16] IMPLICIT Integer16`
    Long(i16),
    /// `unsigned [17] IMPLICIT Unsigned8`
    Unsigned(u8),
    /// `long-unsigned [18] IMPLICIT Unsigned16`
    LongUnsigned(u16),
    /// `compact-array [19] IMPLICIT SEQUENCE { contents-description, array-contents }`
    CompactArray {
        contents_description: u8,
        array_contents: &'a [u8],
    },
    /// `long64 [20] IMPLICIT Integer64`
    Long64(i64),
    /// `long64-unsigned [21] IMPLICIT Unsigned64`
    Long64Unsigned(u64),
    /// `enum [22] IMPLICIT Unsigned8`
    Enum(u8),
    /// `float32 [23] IMPLICIT OCTET STRING (SIZE(4))`
    Float32(f32),
    /// `float64 [24] IMPLICIT OCTET STRING (SIZE(8))`
    Float64(f64),
    /// `date-time [25] IMPLICIT OCTET STRING (SIZE(12))`
    DateTime([u8; 12]),
    /// `date [26] IMPLICIT OCTET STRING (SIZE(5))`
    Date([u8; 5]),
    /// `time [27] IMPLICIT OCTET STRING (SIZE(4))`
    Time([u8; 4]),
    /// `delta-integer [28] IMPLICIT Integer8`
    DeltaInteger(i8),
    /// `delta-long [29] IMPLICIT Integer16`
    DeltaLong(i16),
    /// `delta-double-long [30] IMPLICIT Integer32`
    DeltaDoubleLong(i32),
    /// `delta-unsigned [31] IMPLICIT Unsigned8`
    DeltaUnsigned(u8),
    /// `delta-long-unsigned [32] IMPLICIT Unsigned16`
    DeltaLongUnsigned(u16),
    /// `delta-double-long-unsigned [33] IMPLICIT Unsigned32`
    DeltaDoubleLongUnsigned(u32),
    /// `dont-care [255] IMPLICIT NULL`
    DontCare,
}

/// A concrete type that can be reconstructed from the fields of a
/// [`Data::Structure`].
///
/// This is the [`Data`]-level analogue of a byte-level "recast": given an
/// already-decoded generic [`Data::Structure`] (a borrowed `&[Data]`),
/// implementors map its fields onto a typed struct. See [`Data::recast`].
pub trait FromStructure<'a>: Sized {
    /// Attempt to build `Self` from the structure fields. Returns an error if
    /// the field count or field types do not match the expected shape.
    fn from_structure(fields: &'a [Data<'a>]) -> Result<Self>;
}

/// Common A-XDR codec: encode to / decode from a buffer.
///
/// `get` borrows the decoded bytes for `'a`. An owned type (e.g. a concrete
/// structure) can implement `Codec<'a>` for any `'a`, while [`Data`], which
/// borrows, implements `Codec<'a>` for `Data<'a>`.
pub trait Codec<'a>: Sized {
    /// Encode into `buf`, returning the number of bytes written.
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize>;

    /// Decode from `buf`.
    fn get(buf: &mut Reader<'a>, arena: &mut Arena<'a, Data<'a>>) -> Result<Self>;
}

impl<'a> Codec<'a> for Data<'a> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        Data::put(self, buf)
    }

    fn get(buf: &mut Reader<'a>, arena: &mut Arena<'a, Data<'a>>) -> Result<Self> {
        Data::get(buf, arena)
    }
}

/// Generate an `as_*` accessor that extracts a `Copy`-carrying variant.
macro_rules! data_accessor {
    ($name:ident, $variant:ident, $ty:ty) => {
        pub fn $name(&self) -> Option<$ty> {
            match self {
                Data::$variant(v) => Some(*v),
                _ => None,
            }
        }
    };
}

impl<'a> Data<'a> {
    /// The A-XDR implicit tag number for this value.
    pub fn tag(&self) -> u8 {
        match self {
            Data::NullData => 0,
            Data::Array(_) => 1,
            Data::Structure(_) => 2,
            Data::Boolean(_) => 3,
            Data::BitString { .. } => 4,
            Data::DoubleLong(_) => 5,
            Data::DoubleLongUnsigned(_) => 6,
            Data::OctetString(_) => 9,
            Data::VisibleString(_) => 10,
            Data::Utf8String(_) => 12,
            Data::Bcd(_) => 13,
            Data::Integer(_) => 15,
            Data::Long(_) => 16,
            Data::Unsigned(_) => 17,
            Data::LongUnsigned(_) => 18,
            Data::CompactArray { .. } => 19,
            Data::Long64(_) => 20,
            Data::Long64Unsigned(_) => 21,
            Data::Enum(_) => 22,
            Data::Float32(_) => 23,
            Data::Float64(_) => 24,
            Data::DateTime(_) => 25,
            Data::Date(_) => 26,
            Data::Time(_) => 27,
            Data::DeltaInteger(_) => 28,
            Data::DeltaLong(_) => 29,
            Data::DeltaDoubleLong(_) => 30,
            Data::DeltaUnsigned(_) => 31,
            Data::DeltaLongUnsigned(_) => 32,
            Data::DeltaDoubleLongUnsigned(_) => 33,
            Data::DontCare => 255,
        }
    }

    /// The `i`-th bit of a `BitString` (MSB-first), or `None` if this value is
    /// not a bit-string or `i` is out of range.
    pub fn bit(&self, i: usize) -> Option<u8> {
        match self {
            Data::BitString { bytes, bit_len } => {
                if i >= *bit_len {
                    return None;
                }
                Some((bytes[i / 8] >> (7 - (i % 8))) & 1)
            }
            _ => None,
        }
    }

    // Field accessors: extract a variant's payload as an `Option`. `Copy`
    // payloads are returned by value; borrowed payloads by reference.

    data_accessor!(as_boolean, Boolean, bool);
    data_accessor!(as_double_long, DoubleLong, i32);
    data_accessor!(as_double_long_unsigned, DoubleLongUnsigned, u32);
    data_accessor!(as_bcd, Bcd, i8);
    data_accessor!(as_integer, Integer, i8);
    data_accessor!(as_long, Long, i16);
    data_accessor!(as_unsigned, Unsigned, u8);
    data_accessor!(as_long_unsigned, LongUnsigned, u16);
    data_accessor!(as_long64, Long64, i64);
    data_accessor!(as_long64_unsigned, Long64Unsigned, u64);
    data_accessor!(as_enum, Enum, u8);
    data_accessor!(as_float32, Float32, f32);
    data_accessor!(as_float64, Float64, f64);
    data_accessor!(as_date_time, DateTime, [u8; 12]);
    data_accessor!(as_date, Date, [u8; 5]);
    data_accessor!(as_time, Time, [u8; 4]);
    data_accessor!(as_delta_integer, DeltaInteger, i8);
    data_accessor!(as_delta_long, DeltaLong, i16);
    data_accessor!(as_delta_double_long, DeltaDoubleLong, i32);
    data_accessor!(as_delta_unsigned, DeltaUnsigned, u8);
    data_accessor!(as_delta_long_unsigned, DeltaLongUnsigned, u16);
    data_accessor!(as_delta_double_long_unsigned, DeltaDoubleLongUnsigned, u32);

    /// The `structure` fields as a borrowed slice.
    pub fn as_structure(&self) -> Option<&'a [Data<'a>]> {
        match self {
            Data::Structure(fields) => Some(fields),
            _ => None,
        }
    }

    /// The `array` elements as a borrowed slice.
    pub fn as_array(&self) -> Option<&'a [Data<'a>]> {
        match self {
            Data::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The `octet-string` bytes as a borrowed slice.
    pub fn as_octet_string(&self) -> Option<&'a [u8]> {
        match self {
            Data::OctetString(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// The `visible-string` text.
    pub fn as_visible_string(&self) -> Option<&'a str> {
        match self {
            Data::VisibleString(s) => Some(s),
            _ => None,
        }
    }

    /// The `utf8-string` text.
    pub fn as_utf8_string(&self) -> Option<&'a str> {
        match self {
            Data::Utf8String(s) => Some(s),
            _ => None,
        }
    }

    /// The `bit-string` payload `(bytes, significant bit count)`.
    pub fn as_bit_string(&self) -> Option<(&'a [u8], usize)> {
        match self {
            Data::BitString { bytes, bit_len } => Some((bytes, *bit_len)),
            _ => None,
        }
    }

    /// The `compact-array` `(contents_description, array_contents)`.
    pub fn as_compact_array(&self) -> Option<(u8, &'a [u8])> {
        match self {
            Data::CompactArray {
                contents_description,
                array_contents,
            } => Some((*contents_description, array_contents)),
            _ => None,
        }
    }

    /// Try to reinterpret this value as a concrete structure `T`.
    ///
    /// Returns `Ok` when this is a [`Data::Structure`] whose fields map onto
    /// `T` via [`FromStructure::from_structure`]; otherwise an error.
    pub fn recast<T: FromStructure<'a>>(&self) -> Result<T> {
        match self {
            Data::Structure(fields) => T::from_structure(fields),
            _ => Err(Error::message("expected a Data::Structure")),
        }
    }

    /// Encode tag + content (A-XDR CHOICE alternative).
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut written = buf.put_u8(self.tag())?;
        written += self.put_lc(buf)?;
        Ok(written)
    }

    /// Encode content only (no tag).
    pub fn put_lc(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        match self {
            Data::NullData | Data::DontCare => Ok(0),
            Data::Array(items) | Data::Structure(items) => {
                let mut written = put_length(buf, items.len())?;
                for item in *items {
                    written += item.put(buf)?;
                }
                Ok(written)
            }
            Data::Boolean(b) => Ok(buf.put_u8(if *b { 0xFF } else { 0x00 })?),
            Data::BitString { bytes, bit_len } => put_bit_string(buf, bytes, *bit_len),
            Data::DoubleLong(v) | Data::DeltaDoubleLong(v) => Ok(buf.write(&v.to_be_bytes())?),
            Data::DoubleLongUnsigned(v) | Data::DeltaDoubleLongUnsigned(v) => {
                Ok(buf.write(&v.to_be_bytes())?)
            }
            Data::OctetString(bytes) => put_octet_string(buf, bytes),
            Data::VisibleString(s) => put_string(buf, s),
            Data::Utf8String(s) => put_string(buf, s),
            Data::Bcd(v) | Data::Integer(v) | Data::DeltaInteger(v) => {
                Ok(buf.write(&v.to_be_bytes())?)
            }
            Data::Long(v) | Data::DeltaLong(v) => Ok(buf.write(&v.to_be_bytes())?),
            Data::Unsigned(v) | Data::Enum(v) | Data::DeltaUnsigned(v) => {
                Ok(buf.write(&v.to_be_bytes())?)
            }
            Data::LongUnsigned(v) | Data::DeltaLongUnsigned(v) => {
                Ok(buf.write(&v.to_be_bytes())?)
            }
            Data::CompactArray {
                contents_description,
                array_contents,
            } => {
                let mut written = buf.put_u8(*contents_description)?;
                written += put_octet_string(buf, array_contents)?;
                Ok(written)
            }
            Data::Long64(v) => Ok(buf.write(&v.to_be_bytes())?),
            Data::Long64Unsigned(v) => Ok(buf.write(&v.to_be_bytes())?),
            Data::Float32(f) => Ok(buf.write(&f.to_be_bytes())?),
            Data::Float64(f) => Ok(buf.write(&f.to_be_bytes())?),
            Data::DateTime(b) => Ok(buf.write(b)?),
            Data::Date(b) => Ok(buf.write(b)?),
            Data::Time(b) => Ok(buf.write(b)?),
        }
    }

    /// Decode tag + content.
    pub fn get(buf: &mut Reader<'a>, arena: &mut Arena<'a, Data<'a>>) -> Result<Data<'a>> {
        let tag = buf.get_u8()?;
        Data::get_lc(buf, arena, tag)
    }

    /// Decode content for a known tag.
    pub fn get_lc(buf: &mut Reader<'a>, arena: &mut Arena<'a, Data<'a>>, tag: u8) -> Result<Data<'a>> {
        Ok(match tag {
            0 => Data::NullData,
            1 => Data::Array(read_items(buf, arena)?),
            2 => Data::Structure(read_items(buf, arena)?),
            3 => Data::Boolean(buf.get_u8()? != 0),
            4 => {
                let (bytes, bit_len) = get_bit_string(buf)?;
                Data::BitString { bytes, bit_len }
            }
            5 => Data::DoubleLong(i32::from_be_bytes(read_n::<4>(buf)?)),
            6 => Data::DoubleLongUnsigned(u32::from_be_bytes(read_n::<4>(buf)?)),
            9 => Data::OctetString(get_octet_string(buf)?),
            10 => Data::VisibleString(get_string(buf)?),
            12 => Data::Utf8String(get_string(buf)?),
            13 => Data::Bcd(i8::from_be_bytes(read_n::<1>(buf)?)),
            15 => Data::Integer(i8::from_be_bytes(read_n::<1>(buf)?)),
            16 => Data::Long(i16::from_be_bytes(read_n::<2>(buf)?)),
            17 => Data::Unsigned(u8::from_be_bytes(read_n::<1>(buf)?)),
            18 => Data::LongUnsigned(u16::from_be_bytes(read_n::<2>(buf)?)),
            19 => Data::CompactArray {
                contents_description: buf.get_u8()?,
                array_contents: get_octet_string(buf)?,
            },
            20 => Data::Long64(i64::from_be_bytes(read_n::<8>(buf)?)),
            21 => Data::Long64Unsigned(u64::from_be_bytes(read_n::<8>(buf)?)),
            22 => Data::Enum(u8::from_be_bytes(read_n::<1>(buf)?)),
            23 => Data::Float32(f32::from_be_bytes(read_n::<4>(buf)?)),
            24 => Data::Float64(f64::from_be_bytes(read_n::<8>(buf)?)),
            25 => Data::DateTime(read_n::<12>(buf)?),
            26 => Data::Date(read_n::<5>(buf)?),
            27 => Data::Time(read_n::<4>(buf)?),
            28 => Data::DeltaInteger(i8::from_be_bytes(read_n::<1>(buf)?)),
            29 => Data::DeltaLong(i16::from_be_bytes(read_n::<2>(buf)?)),
            30 => Data::DeltaDoubleLong(i32::from_be_bytes(read_n::<4>(buf)?)),
            31 => Data::DeltaUnsigned(u8::from_be_bytes(read_n::<1>(buf)?)),
            32 => Data::DeltaLongUnsigned(u16::from_be_bytes(read_n::<2>(buf)?)),
            33 => Data::DeltaDoubleLongUnsigned(u32::from_be_bytes(read_n::<4>(buf)?)),
            255 => Data::DontCare,
            _ => return Err(Error::UnknownTag { name: "Data", tag }),
        })
    }
}

fn read_items<'a>(buf: &mut Reader<'a>, arena: &mut Arena<'a, Data<'a>>) -> Result<&'a [Data<'a>]> {
    let n = get_length(buf)?;
    decode_data(buf, arena, n)
}

fn read_n<const N: usize>(buf: &mut Reader<'_>) -> Result<[u8; N]> {
    let mut arr = [0u8; N];
    arr.copy_from_slice(buf.read(N)?);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(d: &Data<'_>) -> Vec<u8> {
        let mut backing = [0u8; 4096];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            d.put(&mut buf).unwrap();
            buf.pos()
        };
        backing[..n].to_vec()
    }

    fn roundtrip(d: Data<'static>) {
        let bytes = encode(&d);
        let mut r = Reader::new(&bytes);
        let mut arena_storage = [core::mem::MaybeUninit::uninit(); 256];
        let mut arena = Arena::new(&mut arena_storage);
        let decoded = Data::get(&mut r, &mut arena).unwrap();
        assert_eq!(encode(&decoded), bytes, "value {d:?}");
    }

    #[test]
    fn fixed_integer_roundtrip() {
        for d in [
            Data::Unsigned(200),
            Data::Integer(-42),
            Data::Long(1000),
            Data::LongUnsigned(60000),
            Data::DoubleLong(-1_000_000),
            Data::DoubleLongUnsigned(4_000_000_000),
            Data::Long64(-9_000_000_000),
            Data::Long64Unsigned(u64::MAX),
            Data::Enum(7),
        ] {
            roundtrip(d);
        }
    }

    #[test]
    fn variable_length_roundtrip() {
        for d in [
            Data::OctetString(b"\x01\x02\x03\x04\x05"),
            Data::VisibleString("hello"),
            Data::Utf8String("héllo"),
            Data::BitString { bytes: b"\xAA\x40", bit_len: 10 },
            Data::Boolean(true),
            Data::NullData,
            Data::DontCare,
        ] {
            roundtrip(d);
        }
    }

    #[test]
    fn composite_roundtrip() {
        let d = Data::Array(&[
            Data::Integer(42),
            Data::VisibleString("hello"),
            Data::Boolean(true),
            Data::Structure(&[Data::OctetString(b"\xDE\xAD"), Data::Enum(3)]),
        ]);
        roundtrip(d);
    }

    #[test]
    fn fixed_octet_string_roundtrip() {
        for d in [
            Data::Float32(1.5),
            Data::Float64(-2.25),
            Data::DateTime([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            Data::Date([1, 2, 3, 4, 5]),
            Data::Time([1, 2, 3, 4]),
        ] {
            roundtrip(d);
        }
    }

    #[test]
    fn known_encoding() {
        assert_eq!(encode(&Data::Unsigned(200)), vec![17, 0xC8]);
        assert_eq!(encode(&Data::Boolean(true)), vec![3, 0xFF]);
        assert_eq!(encode(&Data::NullData), vec![0]);
    }

    #[test]
    fn bit_string_bit_accessor() {
        let d = Data::BitString { bytes: b"\xAA\x40", bit_len: 10 };
        assert_eq!(d.bit(0), Some(1));
        assert_eq!(d.bit(1), Some(0));
        assert_eq!(d.bit(8), Some(0));
        assert_eq!(d.bit(9), Some(1));
        assert_eq!(d.bit(10), None);
        assert_eq!(Data::NullData.bit(0), None);
    }

    /// `scal-unit-type ::= structure { scaler: integer, unit: enum }`.
    ///
    /// A concrete specialization of a [`Data::Structure`], encoded as a
    /// two-field `structure { integer, enum }`. It owns its scalar fields and
    /// implements [`Codec`] to bridge to/from the generic [`Data::Structure`];
    /// it also implements [`FromStructure`] so it can be obtained via
    /// [`Data::recast`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ScalUnitType {
        scaler: i8,
        unit: u8,
    }

    impl ScalUnitType {
        fn new(scaler: i8, unit: u8) -> Self {
            ScalUnitType { scaler, unit }
        }

        fn set_scaler(&mut self, v: i8) {
            self.scaler = v;
        }

        fn set_unit(&mut self, v: u8) {
            self.unit = v;
        }
    }

    impl<'a> FromStructure<'a> for ScalUnitType {
        fn from_structure(fields: &'a [Data<'a>]) -> Result<Self> {
            if fields.len() != 2 {
                return Err(Error::message("expected structure { integer, enum }"));
            }
            let scaler = fields[0]
                .as_integer()
                .ok_or_else(|| Error::message("field 0 must be an integer"))?;
            let unit = fields[1]
                .as_enum()
                .ok_or_else(|| Error::message("field 1 must be an enum"))?;
            Ok(ScalUnitType { scaler, unit })
        }
    }

    impl<'a> Codec<'a> for ScalUnitType {
        fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
            Data::Structure(&[Data::Integer(self.scaler), Data::Enum(self.unit)]).put(buf)
        }

        fn get(buf: &mut Reader<'a>, arena: &mut Arena<'a, Data<'a>>) -> Result<Self> {
            let d = Data::get(buf, arena)?;
            let fields = d
                .as_structure()
                .ok_or_else(|| Error::message("expected a structure"))?;
            ScalUnitType::from_structure(fields)
        }
    }

    #[test]
    fn scal_unit_type_codec() {
        let mut s = ScalUnitType::new(3, 1);
        // Setters.
        s.set_scaler(4);
        assert_eq!(s.scaler, 4);
        s.set_scaler(3);
        s.set_unit(2);
        assert_eq!(s.unit, 2);
        s.set_unit(1);

        // Encode via Codec == Data::Structure { integer, enum }.
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            s.put(&mut buf).unwrap();
            buf.pos()
        };
        assert_eq!(
            &backing[..n],
            &encode(&Data::Structure(&[Data::Integer(3), Data::Enum(1)]))[..]
        );

        // Decode via Codec.
        let mut r = Reader::new(&backing[..n]);
        let mut arena_storage = [core::mem::MaybeUninit::uninit(); 16];
        let mut arena = Arena::new(&mut arena_storage);
        let decoded = ScalUnitType::get(&mut r, &mut arena).unwrap();
        assert_eq!(decoded, s);

        // recast (FromStructure) still works.
        let data = Data::Structure(&[Data::Integer(3), Data::Enum(1)]);
        let s2 = data.recast::<ScalUnitType>().unwrap();
        assert_eq!(s2, s);

        // Reject a non-structure.
        let bad = encode(&Data::Unsigned(7));
        let mut r = Reader::new(&bad);
        let mut arena_storage = [core::mem::MaybeUninit::uninit(); 16];
        let mut arena = Arena::new(&mut arena_storage);
        assert!(ScalUnitType::get(&mut r, &mut arena).is_err());
    }
}