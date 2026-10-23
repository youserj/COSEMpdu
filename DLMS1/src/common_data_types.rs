//! Typed values of the DLMS UA "common data types" (clause 7.4).
//!
//! Concrete, fixed-shape value types that wrap a single [`Data`] variant and
//! implement [`Codec`] (encode/decode) plus [`StreamSink`] (streaming decode).

use cosempdu::buffer::ByteBuffer;
use cosempdu::data::{Codec, Data};
use cosempdu::stream::StreamSink;

/// Shared body for integer/float scalar types (from/to big-endian bytes).
macro_rules! num_scalar {
    ($name:ident, $ty:ty, $variant:ident, $tag:expr) => {
        impl Codec for $name {
            fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
                Data::$variant(self.0).put(buf)
            }

            fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
                match data {
                    Data::$variant(v) => {
                        self.0 = *v;
                        Ok(())
                    }
                    _ => Err(cosempdu::Error::UnexpectedTag {
                        name: stringify!($variant),
                        actual: data.tag(),
                    }),
                }
            }

            fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
                Some(self)
            }
        }

        impl StreamSink for $name {
            fn scalar(&mut self, tag: u8, bytes: &[u8], _index: usize) -> cosempdu::Result<()> {
                const N: usize = core::mem::size_of::<$ty>();
                if tag != $tag || bytes.len() != N {
                    return Err(cosempdu::Error::Message(concat!(
                        stringify!($name),
                        " scalar has wrong tag/size"
                    )));
                }
                let arr: [u8; N] = bytes
                    .try_into()
                    .map_err(|_| cosempdu::Error::Message("scalar has wrong size"))?;
                self.0 = <$ty>::from_be_bytes(arr);
                Ok(())
            }
        }
    };
}

/// Integer scalar (derives `Eq`).
macro_rules! int_scalar {
    ($name:ident, $ty:ty, $variant:ident, $tag:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name(pub $ty);
        num_scalar!($name, $ty, $variant, $tag);
    };
}

/// Float scalar (`f32`/`f64` are not `Eq`).
macro_rules! float_scalar {
    ($name:ident, $ty:ty, $variant:ident, $tag:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Default)]
        pub struct $name(pub $ty);
        num_scalar!($name, $ty, $variant, $tag);
    };
}

/// Fixed-size octet-string scalar (`date`, `time`, …).
macro_rules! bytes_scalar {
    ($name:ident, $variant:ident, $tag:expr, $size:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name(pub [u8; $size]);

        impl Codec for $name {
            fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
                Data::$variant(self.0).put(buf)
            }

            fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
                match data {
                    Data::$variant(v) => {
                        self.0 = *v;
                        Ok(())
                    }
                    _ => Err(cosempdu::Error::UnexpectedTag {
                        name: stringify!($variant),
                        actual: data.tag(),
                    }),
                }
            }

            fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
                Some(self)
            }
        }

        impl StreamSink for $name {
            fn scalar(&mut self, tag: u8, bytes: &[u8], _index: usize) -> cosempdu::Result<()> {
                if tag != $tag || bytes.len() != $size {
                    return Err(cosempdu::Error::Message(concat!(
                        stringify!($name),
                        " scalar has wrong tag/size"
                    )));
                }
                self.0.copy_from_slice(bytes);
                Ok(())
            }
        }
    };
}

/// UTF-8 string blob with a fixed buffer (`visible-string`, `utf8-string`).
macro_rules! string_type {
    ($name:ident, $variant:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name<const N: usize> {
            pub buf: [u8; N],
            pub len: usize,
        }

        impl<const N: usize> Default for $name<N> {
            fn default() -> Self {
                $name { buf: [0; N], len: 0 }
            }
        }

        impl<const N: usize> Codec for $name<N> {
            fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
                let s = core::str::from_utf8(&self.buf[..self.len])
                    .map_err(|e| cosempdu::Error::InvalidUtf8 { valid_up_to: e.valid_up_to() })?;
                Data::$variant(s).put(buf)
            }

            fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
                match data {
                    Data::$variant(s) => {
                        let b = s.as_bytes();
                        if b.len() > N {
                            return Err(cosempdu::Error::InputTooLarge { len: b.len(), max: N });
                        }
                        self.buf[..b.len()].copy_from_slice(b);
                        self.len = b.len();
                        Ok(())
                    }
                    _ => Err(cosempdu::Error::UnexpectedTag {
                        name: stringify!($variant),
                        actual: data.tag(),
                    }),
                }
            }

            fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
                Some(self)
            }
        }

        impl<const N: usize> StreamSink for $name<N> {
            fn blob_begin(&mut self, _tag: u8, len: usize) -> cosempdu::Result<()> {
                if len > N {
                    return Err(cosempdu::Error::InputTooLarge { len, max: N });
                }
                self.len = len;
                Ok(())
            }

            fn blob_write(&mut self, bytes: &[u8], _index: usize, offset: usize) -> cosempdu::Result<()> {
                let end = offset + bytes.len();
                if end > N {
                    return Err(cosempdu::Error::InputTooLarge { len: end, max: N });
                }
                self.buf[offset..end].copy_from_slice(bytes);
                Ok(())
            }
        }
    };
}



/// `double-long-unsigned` (Unsigned32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DoubleLongUnsigned(pub u32);

impl Codec for DoubleLongUnsigned {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::DoubleLongUnsigned(self.0).put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        match data {
            Data::DoubleLongUnsigned(v) => {
                self.0 = *v;
                Ok(())
            }
            _ => Err(cosempdu::Error::UnexpectedTag {
                name: "double-long-unsigned",
                actual: data.tag(),
            }),
        }
    }

    fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
        Some(self)
    }
}

impl StreamSink for DoubleLongUnsigned {
    fn scalar(&mut self, tag: u8, bytes: &[u8], _index: usize) -> cosempdu::Result<()> {
        if tag != 6 || bytes.len() != 4 {
            return Err(cosempdu::Error::Message(
                "DoubleLongUnsigned expects double-long-unsigned",
            ));
        }
        self.0 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Ok(())
    }
}

/// `date-time` (12-byte octet-string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DateTime(pub [u8; 12]);

impl Codec for DateTime {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::DateTime(self.0).put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        match data {
            Data::DateTime(v) => {
                self.0 = *v;
                Ok(())
            }
            _ => Err(cosempdu::Error::UnexpectedTag {
                name: "date-time",
                actual: data.tag(),
            }),
        }
    }

    fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
        Some(self)
    }
}

impl StreamSink for DateTime {
    fn scalar(&mut self, tag: u8, bytes: &[u8], _index: usize) -> cosempdu::Result<()> {
        if tag != 25 || bytes.len() != 12 {
            return Err(cosempdu::Error::Message("DateTime expects date-time"));
        }
        self.0.copy_from_slice(bytes);
        Ok(())
    }
}

/// `octet-string` of up to `N` bytes (variable length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OctetString<const N: usize> {
    pub buf: [u8; N],
    pub len: usize,
}

impl<const N: usize> Default for OctetString<N> {
    fn default() -> Self {
        OctetString { buf: [0; N], len: 0 }
    }
}

impl<const N: usize> Codec for OctetString<N> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::OctetString(&self.buf[..self.len]).put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        match data {
            Data::OctetString(b) => {
                if b.len() > N {
                    return Err(cosempdu::Error::InputTooLarge { len: b.len(), max: N });
                }
                self.buf[..b.len()].copy_from_slice(b);
                self.len = b.len();
                Ok(())
            }
            _ => Err(cosempdu::Error::UnexpectedTag {
                name: "octet-string",
                actual: data.tag(),
            }),
        }
    }

    fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
        Some(self)
    }
}

impl<const N: usize> StreamSink for OctetString<N> {
    fn blob_begin(&mut self, _tag: u8, len: usize) -> cosempdu::Result<()> {
        if len > N {
            return Err(cosempdu::Error::InputTooLarge { len, max: N });
        }
        self.len = len;
        Ok(())
    }

    fn blob_write(&mut self, bytes: &[u8], _index: usize, offset: usize) -> cosempdu::Result<()> {
        let end = offset + bytes.len();
        if end > N {
            return Err(cosempdu::Error::InputTooLarge { len: end, max: N });
        }
        self.buf[offset..end].copy_from_slice(bytes);
        Ok(())
    }
}


/// Fixed-length `octet-string` (always exactly `N` bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OctetStringSized<const N: usize>(pub [u8; N]);

impl<const N: usize> Default for OctetStringSized<N> {
    fn default() -> Self {
        OctetStringSized([0; N])
    }
}

impl<const N: usize> Codec for OctetStringSized<N> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::OctetString(&self.0).put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        match data {
            Data::OctetString(b) => {
                if b.len() != N {
                    return Err(cosempdu::Error::Message("octet-string has wrong length"));
                }
                self.0.copy_from_slice(b);
                Ok(())
            }
            _ => Err(cosempdu::Error::UnexpectedTag {
                name: "octet-string",
                actual: data.tag(),
            }),
        }
    }

    fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
        Some(self)
    }
}

impl<const N: usize> StreamSink for OctetStringSized<N> {
    fn blob_begin(&mut self, _tag: u8, len: usize) -> cosempdu::Result<()> {
        if len != N {
            return Err(cosempdu::Error::Message("octet-string has wrong length"));
        }
        Ok(())
    }

    fn blob_write(&mut self, bytes: &[u8], _index: usize, offset: usize) -> cosempdu::Result<()> {
        let end = offset + bytes.len();
        if end > N {
            return Err(cosempdu::Error::InputTooLarge { len: end, max: N });
        }
        self.0[offset..end].copy_from_slice(bytes);
        Ok(())
    }
}

// ---- scalar common data types ----

// ---- scalar common data types ----

/// `boolean` (BOOLEAN: `0x00` = false, otherwise true).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Boolean(pub bool);

impl Codec for Boolean {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::Boolean(self.0).put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        match data {
            Data::Boolean(v) => {
                self.0 = *v;
                Ok(())
            }
            _ => Err(cosempdu::Error::UnexpectedTag {
                name: "boolean",
                actual: data.tag(),
            }),
        }
    }

    fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
        Some(self)
    }
}

impl StreamSink for Boolean {
    fn scalar(&mut self, tag: u8, bytes: &[u8], _index: usize) -> cosempdu::Result<()> {
        if tag != 3 || bytes.len() != 1 {
            return Err(cosempdu::Error::Message("Boolean scalar has wrong tag/size"));
        }
        self.0 = bytes[0] != 0;
        Ok(())
    }
}

/// `null-data` (NULL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NullData;

impl Codec for NullData {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::NullData.put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        match data {
            Data::NullData => Ok(()),
            _ => Err(cosempdu::Error::UnexpectedTag {
                name: "null-data",
                actual: data.tag(),
            }),
        }
    }

    fn stream_sink(&mut self) -> Option<&mut (dyn StreamSink + '_)> {
        Some(self)
    }
}

impl StreamSink for NullData {
    fn scalar(&mut self, tag: u8, bytes: &[u8], _index: usize) -> cosempdu::Result<()> {
        if tag != 0 || !bytes.is_empty() {
            return Err(cosempdu::Error::Message("NullData scalar has wrong tag/size"));
        }
        Ok(())
    }
}


// Numeric scalars (integers, floats) and fixed-size octet-strings.
int_scalar!(DoubleLong, i32, DoubleLong, 5);
int_scalar!(Bcd, i8, Bcd, 13);
int_scalar!(Integer, i8, Integer, 15);
int_scalar!(Long, i16, Long, 16);
int_scalar!(Unsigned, u8, Unsigned, 17);
int_scalar!(LongUnsigned, u16, LongUnsigned, 18);
int_scalar!(Long64, i64, Long64, 20);
int_scalar!(Long64Unsigned, u64, Long64Unsigned, 21);
int_scalar!(Enum, u8, Enum, 22);
float_scalar!(Float32, f32, Float32, 23);
float_scalar!(Float64, f64, Float64, 24);
bytes_scalar!(Date, Date, 26, 5);
bytes_scalar!(Time, Time, 27, 4);
int_scalar!(DeltaInteger, i8, DeltaInteger, 28);
int_scalar!(DeltaLong, i16, DeltaLong, 29);
int_scalar!(DeltaDoubleLong, i32, DeltaDoubleLong, 30);
int_scalar!(DeltaUnsigned, u8, DeltaUnsigned, 31);
int_scalar!(DeltaLongUnsigned, u16, DeltaLongUnsigned, 32);
int_scalar!(DeltaDoubleLongUnsigned, u32, DeltaDoubleLongUnsigned, 33);

// String blobs.
string_type!(VisibleString, VisibleString);
string_type!(Utf8String, Utf8String);


// ---- non-streamable compound types (Codec only) ----

/// `bit-string` (packed octets + significant bit count). Not streamable: the
/// length prefix carries the bit count, which the streaming decoder does not handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitString<const N: usize> {
    pub bytes: [u8; N],
    pub bit_len: usize,
}

impl<const N: usize> Default for BitString<N> {
    fn default() -> Self {
        BitString { bytes: [0; N], bit_len: 0 }
    }
}

impl<const N: usize> Codec for BitString<N> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        let num_octets = self.bit_len.div_ceil(8);
        if num_octets > N {
            return Err(cosempdu::Error::InputTooLarge { len: num_octets, max: N });
        }
        Data::BitString {
            bytes: &self.bytes[..num_octets],
            bit_len: self.bit_len,
        }
        .put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        match data {
            Data::BitString { bytes, bit_len } => {
                if bytes.len() > N {
                    return Err(cosempdu::Error::InputTooLarge { len: bytes.len(), max: N });
                }
                self.bytes[..bytes.len()].copy_from_slice(bytes);
                self.bit_len = *bit_len;
                Ok(())
            }
            _ => Err(cosempdu::Error::UnexpectedTag {
                name: "bit-string",
                actual: data.tag(),
            }),
        }
    }
}

/// `compact-array` (`contents-description` + packed `array-contents`). Not
/// streamable: it is a compound (a byte followed by an octet-string).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactArray<const N: usize> {
    pub contents_description: u8,
    pub array_contents: [u8; N],
    pub len: usize,
}

impl<const N: usize> Default for CompactArray<N> {
    fn default() -> Self {
        CompactArray {
            contents_description: 0,
            array_contents: [0; N],
            len: 0,
        }
    }
}

impl<const N: usize> Codec for CompactArray<N> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        Data::CompactArray {
            contents_description: self.contents_description,
            array_contents: &self.array_contents[..self.len],
        }
        .put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> cosempdu::Result<()> {
        match data {
            Data::CompactArray {
                contents_description,
                array_contents,
            } => {
                if array_contents.len() > N {
                    return Err(cosempdu::Error::InputTooLarge {
                        len: array_contents.len(),
                        max: N,
                    });
                }
                self.contents_description = *contents_description;
                self.array_contents[..array_contents.len()].copy_from_slice(array_contents);
                self.len = array_contents.len();
                Ok(())
            }
            _ => Err(cosempdu::Error::UnexpectedTag {
                name: "compact-array",
                actual: data.tag(),
            }),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use cosempdu::buffer::Reader;
    use cosempdu::data::Arena;

    fn roundtrip<T: Codec + Default + PartialEq + core::fmt::Debug>(data: &Data<'_>, expected: T) {
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            data.put(&mut buf).unwrap()
        };
        let mut arena_storage = [core::mem::MaybeUninit::uninit(); 8];
        let mut arena = Arena::new(&mut arena_storage);
        let mut reader = Reader::new(&backing[..n]);
        let decoded: T = T::get(&mut reader, &mut arena).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn scalars_roundtrip() {
        roundtrip(&Data::Boolean(true), Boolean(true));
        roundtrip(&Data::DoubleLong(-123), DoubleLong(-123));
        roundtrip(&Data::DoubleLongUnsigned(123), DoubleLongUnsigned(123));
        roundtrip(&Data::Bcd(9), Bcd(9));
        roundtrip(&Data::Integer(-5), Integer(-5));
        roundtrip(&Data::Long(-300), Long(-300));
        roundtrip(&Data::Unsigned(200), Unsigned(200));
        roundtrip(&Data::LongUnsigned(40000), LongUnsigned(40000));
        roundtrip(&Data::Long64(-123456789), Long64(-123456789));
        roundtrip(&Data::Long64Unsigned(123456789), Long64Unsigned(123456789));
        roundtrip(&Data::Enum(7), Enum(7));
        roundtrip(&Data::Float32(1.5), Float32(1.5));
        roundtrip(&Data::Float64(2.25), Float64(2.25));
        roundtrip(&Data::DateTime([1; 12]), DateTime([1; 12]));
        roundtrip(&Data::Date([1, 2, 3, 4, 5]), Date([1, 2, 3, 4, 5]));
        roundtrip(&Data::Time([1, 2, 3, 4]), Time([1, 2, 3, 4]));
        roundtrip(&Data::DeltaInteger(-5), DeltaInteger(-5));
        roundtrip(&Data::DeltaDoubleLongUnsigned(42), DeltaDoubleLongUnsigned(42));
        roundtrip(&Data::NullData, NullData);
        roundtrip(&Data::OctetString(&[1, 2, 3, 4]), OctetStringSized::<4>([1, 2, 3, 4]));
    }

    #[test]
    fn strings_roundtrip() {
        let data = Data::VisibleString("hello");
        let mut backing = [0u8; 64];
        let n = { let mut buf = ByteBuffer::new(&mut backing); data.put(&mut buf).unwrap() };
        let mut arena_storage = [core::mem::MaybeUninit::uninit(); 8];
        let mut arena = Arena::new(&mut arena_storage);
        let mut reader = Reader::new(&backing[..n]);
        let decoded = VisibleString::<8>::get(&mut reader, &mut arena).unwrap();
        assert_eq!(&decoded.buf[..decoded.len], b"hello");
    }

    #[test]
    fn compound_roundtrip() {
        // BitString
        {
            let data = Data::BitString { bytes: &[0b1010_0000], bit_len: 4 };
            let mut backing = [0u8; 64];
            let n = { let mut buf = ByteBuffer::new(&mut backing); data.put(&mut buf).unwrap() };
            let mut arena_storage = [core::mem::MaybeUninit::uninit(); 8];
            let mut arena = Arena::new(&mut arena_storage);
            let mut reader = Reader::new(&backing[..n]);
            let decoded = BitString::<4>::get(&mut reader, &mut arena).unwrap();
            assert_eq!(decoded.bit_len, 4);
            assert_eq!(decoded.bytes[0], 0b1010_0000);
        }
        // CompactArray
        {
            let data = Data::CompactArray { contents_description: 7, array_contents: &[1, 2, 3] };
            let mut backing = [0u8; 64];
            let n = { let mut buf = ByteBuffer::new(&mut backing); data.put(&mut buf).unwrap() };
            let mut arena_storage = [core::mem::MaybeUninit::uninit(); 8];
            let mut arena = Arena::new(&mut arena_storage);
            let mut reader = Reader::new(&backing[..n]);
            let decoded = CompactArray::<8>::get(&mut reader, &mut arena).unwrap();
            assert_eq!(decoded.contents_description, 7);
            assert_eq!(&decoded.array_contents[..decoded.len], &[1, 2, 3]);
        }
    }
}

