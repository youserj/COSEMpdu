//! Streaming A-XDR decoder (IEC 61334-6:2000).
//!
//! A push parser that decodes a single [`crate::data::Data`] value from a byte
//! stream fed in arbitrary chunks (e.g. segmented xDLMS APDU blocks) without
//! buffering the whole value. Large leaf contents (octet-string, …) are streamed
//! directly into a [`StreamSink`].

use crate::error::{Error, Result};

/// Receives the events of a streaming decode.
///
/// The trait is object-safe so a concrete attribute value type can implement it
/// and receive the decoded value directly into its own fields. Methods that a
/// given shape does not use default to an error (e.g. a scalar type only
/// overrides [`StreamSink::scalar`]).
pub trait StreamSink {
    /// A fixed-size scalar leaf: `tag` plus its big-endian content bytes.
    ///
    /// `index` is the 0-based index of the current element within the outermost
    /// composite (0 for a top-level scalar value).
    fn scalar(&mut self, _tag: u8, _bytes: &[u8], _index: usize) -> Result<()> {
        Err(Error::UnexpectedScalar)
    }

    /// A length-prefixed blob (octet/visible/utf8-string) begins.
    fn blob_begin(&mut self, _tag: u8, _len: usize) -> Result<()> {
        Err(Error::UnexpectedBlob)
    }

    /// A chunk of blob content.
    ///
    /// `index` is the 0-based index of the current element within the outermost
    /// composite; `offset` is how many bytes of this blob were already delivered.
    fn blob_write(&mut self, _bytes: &[u8], _index: usize, _offset: usize) -> Result<()> {
        Err(Error::UnexpectedBlob)
    }

    /// A blob has been fully received.
    fn blob_end(&mut self) -> Result<()> {
        Ok(())
    }

    /// A composite (array/structure) begins with `count` elements.
    fn composite_begin(&mut self, _tag: u8, _count: usize) -> Result<()> {
        Err(Error::UnexpectedComposite)
    }

    /// A composite has been fully received.
    fn composite_end(&mut self) -> Result<()> {
        Ok(())
    }

    /// The whole value was decoded successfully.
    fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}


/// Fixed content size (bytes) of a scalar tag, or `None` otherwise.
pub(crate) fn scalar_size(tag: u8) -> Option<usize> {
    Some(match tag {
        0 | 255 => 0,
        3 | 13 | 15 | 17 | 22 | 28 | 31 => 1,
        16 | 18 | 29 | 32 => 2,
        5 | 6 | 23 | 27 | 30 | 33 => 4,
        26 => 5,
        20 | 21 | 24 => 8,
        25 => 12,
        _ => return None,
    })
}

/// Length-prefixed byte blobs (octet-string, visible-string, utf8-string).
fn is_blob(tag: u8) -> bool {
    matches!(tag, 9 | 10 | 12)
}

/// Composite aggregates (array, structure).
fn is_composite(tag: u8) -> bool {
    matches!(tag, 1 | 2)
}

const MAX_DEPTH: usize = 16;

#[derive(Clone, Copy)]
enum State {
    /// Expecting a tag byte (top level or the next element of a composite).
    Tag,
    /// Accumulating a fixed-size scalar.
    Scalar { tag: u8, size: usize, filled: usize, buf: [u8; 12] },
    /// Reading the first octet of a variable-length integer (blob length / element count).
    LengthFirst { tag: u8, is_composite: bool },
    /// Reading the remaining octets of a long-form variable-length integer.
    LengthRest { tag: u8, is_composite: bool, num_bytes: usize, filled: usize, value: u64 },
    /// Streaming blob content.
    Blob { total: usize, remaining: usize },
    /// The whole value has been decoded.
    Done,
}

/// Streaming A-XDR decoder for a single value.
pub struct StreamDecoder<'s, S: StreamSink + ?Sized> {
    sink: &'s mut S,
    state: State,
    stack: [usize; MAX_DEPTH],
    totals: [usize; MAX_DEPTH],
    stack_len: usize,
}

impl<'s, S: StreamSink + ?Sized> StreamDecoder<'s, S> {
    /// Wrap `sink`; the decoder will drive it as bytes are pushed.
    pub fn new(sink: &'s mut S) -> Self {
        StreamDecoder {
            sink,
            state: State::Tag,
            stack: [0; MAX_DEPTH],
            totals: [0; MAX_DEPTH],
            stack_len: 0,
        }
    }

    /// Feed a chunk of the value's A-XDR encoding. Chunks may split the stream
    /// at any byte boundary.
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<()> {
        if matches!(self.state, State::Done) && !bytes.is_empty() {
            return Err(Error::TrailingData);
        }
        while !bytes.is_empty() {
            match self.state {
                State::Blob { total, remaining } => {
                    let n = remaining.min(bytes.len());
                    let index = self.index();
                    self.sink.blob_write(&bytes[..n], index, total - remaining)?;
                    bytes = &bytes[n..];
                    if n == remaining {
                        self.sink.blob_end()?;
                        self.end_element()?;
                    } else {
                        self.state = State::Blob { total, remaining: remaining - n };
                    }
                }
                _ => {
                    let b = bytes[0];
                    bytes = &bytes[1..];
                    self.step(b)?;
                }
            }
        }
        Ok(())
    }

    /// Signal end of stream; fails if the value is incomplete.
    pub fn finish(&mut self) -> Result<()> {
        match self.state {
            State::Done => self.sink.finish(),
            _ => Err(Error::IncompleteValue),
        }
    }


    fn step(&mut self, b: u8) -> Result<()> {
        match self.state {
            State::Tag => {
                let tag = b;
                if let Some(size) = scalar_size(tag) {
                    if size == 0 {
                        let index = self.index();
                        self.sink.scalar(tag, &[], index)?;
                        self.end_element()?;
                    } else {
                        self.state = State::Scalar { tag, size, filled: 0, buf: [0; 12] };
                    }
                } else if is_blob(tag) {
                    self.state = State::LengthFirst { tag, is_composite: false };
                } else if is_composite(tag) {
                    self.state = State::LengthFirst { tag, is_composite: true };
                } else {
                    return Err(Error::UnknownTag { name: "Data", tag });
                }
                Ok(())
            }
            State::Scalar { tag, size, filled, mut buf } => {
                buf[filled] = b;
                if filled + 1 == size {
                    let index = self.index();
                    self.sink.scalar(tag, &buf[..size], index)?;
                    self.end_element()?;
                } else {
                    self.state = State::Scalar { tag, size, filled: filled + 1, buf };
                }
                Ok(())
            }
            State::LengthFirst { tag, is_composite } => {
                if b < 0x80 {
                    self.enter_len(tag, is_composite, usize::from(b))?;
                } else {
                    let n = usize::from(b & 0x7F);
                    if n == 0 {
                        return Err(Error::InvalidLengthEncoding);
                    }
                    self.state = State::LengthRest { tag, is_composite, num_bytes: n, filled: 0, value: 0 };
                }
                Ok(())
            }
            State::LengthRest { tag, is_composite, num_bytes, filled, value } => {
                let value = (value << 8) | u64::from(b);
                if filled + 1 == num_bytes {
                    self.enter_len(tag, is_composite, value as usize)?;
                } else {
                    self.state = State::LengthRest { tag, is_composite, num_bytes, filled: filled + 1, value };
                }
                Ok(())
            }
            State::Blob { .. } => Err(Error::InternalState),
            State::Done => Err(Error::TrailingData),
        }
    }

    fn enter_len(&mut self, tag: u8, is_composite: bool, len: usize) -> Result<()> {
        if is_composite {
            self.sink.composite_begin(tag, len)?;
            if self.stack_len >= MAX_DEPTH {
                return Err(Error::NestingTooDeep);
            }
            self.totals[self.stack_len] = len;
            self.stack[self.stack_len] = len;
            self.stack_len += 1;
            if len == 0 {
                self.end_element()?;
            } else {
                self.state = State::Tag;
            }
        } else {
            self.sink.blob_begin(tag, len)?;
            if len == 0 {
                self.sink.blob_end()?;
                self.end_element()?;
            } else {
                self.state = State::Blob { total: len, remaining: len };
            }
        }
        Ok(())
    }

    /// 0-based index of the current element within the outermost composite
    /// (0 for a top-level value).
    fn index(&self) -> usize {
        if self.stack_len == 0 {
            0
        } else {
            self.totals[0] - self.stack[0]
        }
    }

    fn end_element(&mut self) -> Result<()> {
        loop {
            if self.stack_len == 0 {
                self.state = State::Done;
                return Ok(());
            }
            let remaining = &mut self.stack[self.stack_len - 1];
            if *remaining > 1 {
                *remaining -= 1;
                self.state = State::Tag;
                return Ok(());
            }
            self.stack_len -= 1;
            self.sink.composite_end()?;
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::ByteBuffer;
    use crate::data::Data;

    fn encode(d: &Data<'_>) -> Vec<u8> {
        let mut backing = [0u8; 4096];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            d.put(&mut buf).unwrap()
        };
        backing[..n].to_vec()
    }

    #[derive(Default)]
    struct BlobSink {
        tag: u8,
        len: usize,
        content: Vec<u8>,
    }

    impl StreamSink for BlobSink {
        fn blob_begin(&mut self, tag: u8, len: usize) -> Result<()> {
            self.tag = tag;
            self.len = len;
            Ok(())
        }
        fn blob_write(&mut self, bytes: &[u8], _index: usize, _offset: usize) -> Result<()> {
            self.content.extend_from_slice(bytes);
            Ok(())
        }
    }

    #[derive(Default)]
    struct ArraySink {
        tag: u8,
        count: usize,
        values: Vec<u8>,
    }

    impl StreamSink for ArraySink {
        fn composite_begin(&mut self, tag: u8, count: usize) -> Result<()> {
            self.tag = tag;
            self.count = count;
            Ok(())
        }
        fn scalar(&mut self, tag: u8, bytes: &[u8], _index: usize) -> Result<()> {
            assert_eq!(tag, 17, "expected unsigned element");
            self.values.push(bytes[0]);
            Ok(())
        }
    }

    #[derive(Default)]
    struct ScalarSink {
        tag: u8,
        bytes: Vec<u8>,
    }

    impl StreamSink for ScalarSink {
        fn scalar(&mut self, tag: u8, bytes: &[u8], _index: usize) -> Result<()> {
            self.tag = tag;
            self.bytes = bytes.to_vec();
            Ok(())
        }
    }

    #[test]
    fn octet_string_across_chunks() {
        let content: Vec<u8> = (0..60u8).collect();
        let value = Data::OctetString(&content);
        let encoded = encode(&value);

        let mut sink = BlobSink::default();
        {
            let mut dec = StreamDecoder::new(&mut sink);
            for chunk in encoded.chunks(20) {
                dec.push(chunk).unwrap();
            }
            dec.finish().unwrap();
        }
        assert_eq!(sink.tag, 9);
        assert_eq!(sink.len, 60);
        assert_eq!(sink.content, content);
    }

    #[test]
    fn array_of_unsigned_across_chunks() {
        let items: Vec<Data<'static>> = (0..60u8).map(|i| Data::Unsigned(i)).collect();
        let value = Data::Array(&items);
        let encoded = encode(&value);

        let mut sink = ArraySink::default();
        {
            let mut dec = StreamDecoder::new(&mut sink);
            for chunk in encoded.chunks(20) {
                dec.push(chunk).unwrap();
            }
            dec.finish().unwrap();
        }
        assert_eq!(sink.tag, 1);
        assert_eq!(sink.count, 60);
        assert_eq!(sink.values, (0..60u8).collect::<Vec<_>>());
    }

    #[test]
    fn scalar_split_mid_content() {
        let value = Data::DoubleLongUnsigned(0x1234_5678);
        let encoded = encode(&value);

        let mut sink = ScalarSink::default();
        {
            let mut dec = StreamDecoder::new(&mut sink);
            dec.push(&encoded[..3]).unwrap();
            dec.push(&encoded[3..]).unwrap();
            dec.finish().unwrap();
        }
        assert_eq!(sink.tag, 6);
        assert_eq!(sink.bytes, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn long_form_length_blob() {
        let content: Vec<u8> = (0..300usize).map(|i| (i % 251) as u8).collect();
        let value = Data::OctetString(&content);
        let encoded = encode(&value);

        let mut sink = BlobSink::default();
        {
            let mut dec = StreamDecoder::new(&mut sink);
            for chunk in encoded.chunks(20) {
                dec.push(chunk).unwrap();
            }
            dec.finish().unwrap();
        }
        assert_eq!(sink.tag, 9);
        assert_eq!(sink.len, 300);
        assert_eq!(sink.content, content);
    }

    #[test]
    fn incomplete_value_is_an_error() {
        let value = Data::DoubleLongUnsigned(1);
        let encoded = encode(&value);

        let mut sink = ScalarSink::default();
        let mut dec = StreamDecoder::new(&mut sink);
        dec.push(&encoded[..2]).unwrap();
        assert!(dec.finish().is_err());
    }
}

