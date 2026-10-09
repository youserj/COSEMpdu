//! X.690 BER length/tag primitives and ED (encode/decode) helpers.
//!
//! Mirrors `src/COSEMpdu/x690.py`: provides the [`Length`] component, tag
//! encoding/decoding, and the `ed2buf` / `ed2ed` / `recast` composition
//! helpers built on the [`ED`] trait.

use bytebuffer::{ByteBuffer, Reader};
use crate::error::{Error, Result};
use crate::x680::{Class, Tag};

// ---------------------------------------------------------------------------
// Length component (X.690 §8.1.3)
// ---------------------------------------------------------------------------

/// Length component of a BER TLV.
///
/// * `value >= 0` — definite length in octets.
/// * `value == -1` — indefinite form (EOC terminated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Length {
    pub value: i64,
}

impl Length {
    /// Validate and construct a length value.
    pub fn new(value: i64) -> Result<Self> {
        if value < -1 {
            return Err(Error::InvalidLength { value });
        }
        Ok(Length { value })
    }

    /// Number of octets required to encode this length (X.690 §8.1.3.4, §8.1.3.6).
    pub fn encoded_len(&self) -> usize {
        if self.value == -1 {
            return 1;
        }
        if self.value < 0x80 {
            return 1;
        }
        // Long definite form: 1 (length-of-length) + minimal value bytes.
        let bits = 64 - (self.value as u64).leading_zeros();
        let num_value_bytes = ((bits + 7) / 8) as usize;
        1 + num_value_bytes
    }

    /// Decode a length from the buffer (advancing it) per X.690 §8.1.3.
    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        let first = buf.get_u8()?;
        if first & 0x80 == 0 {
            return Ok(Length {
                value: i64::from(first),
            });
        }
        let len = usize::from(first & 0x7F);
        if len == 0 {
            return Ok(Length { value: -1 });
        }
        let value = buf.get_uint(len)? as i64;
        Ok(Length { value })
    }

    /// Encode the length to the buffer (advancing it) per X.690 §8.1.3.
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        if self.value == -1 {
            return Ok(buf.put_u8(0x80)?);
        }
        if self.value < 0x80 {
            return Ok(buf.put_u8(self.value as u8)?);
        }
        let bits = 64 - (self.value as u64).leading_zeros();
        let num_bytes = ((bits + 7) / 8) as usize;
        let mut written = buf.put_u8(0x80 | num_bytes as u8)?;
        let be = (self.value as u64).to_be_bytes();
        written += buf.write(&be[be.len() - num_bytes..])?;
        Ok(written)
    }
}

impl core::fmt::Display for Length {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.value == -1 {
            write!(f, "indefinite")
        } else {
            write!(f, "{}", self.value)
        }
    }
}

/// Encode a raw length value per X.690 §8.1.3 (minimal octets required).
pub fn put_length(buf: &mut ByteBuffer<'_>, value: i64) -> Result<usize> {
    Length::new(value)?.put(buf)
}

// ---------------------------------------------------------------------------
// Tag encoding/decoding (X.690 §8.1.2)
// ---------------------------------------------------------------------------

/// Decode a BER tag (advancing the buffer) per X.690 §8.1.2.
pub fn get_tag(buf: &mut Reader<'_>) -> Result<Tag> {
    let first = buf.get_u8()?;
    let class = Class::from_bits(first);
    let constructed = first & 0x20 != 0;
    let mut tag_number = u64::from(first & 0x1F);
    if tag_number == 0x1F {
        // High-tag-number form (X.690 §8.1.2.4)
        tag_number = 0;
        loop {
            let byte = buf.get_u8()?;
            tag_number = (tag_number << 7) | u64::from(byte & 0x7F);
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    Ok(Tag {
        class,
        number: tag_number,
        constructed,
    })
}

/// Encode a BER tag (advancing the buffer) per X.690 §8.1.2.
pub fn put_tag(buf: &mut ByteBuffer<'_>, tag: &Tag) -> Result<usize> {
    let mut initial = tag.class.bits();
    if tag.constructed {
        initial |= 0x20;
    }
    if tag.number < 0x1F {
        return Ok(buf.put_u8(initial | tag.number as u8)?);
    }
    let mut written = buf.put_u8(initial | 0x1F)?;
    // Encode tag number in 7-bit chunks, MSB first, last chunk bit 8 = 0.
    let mut chunks = [0u8; 10];
    let mut count = 0usize;
    let mut n = tag.number;
    loop {
        chunks[count] = (n & 0x7F) as u8;
        count += 1;
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    for i in (0..count).rev() {
        let mut chunk = chunks[i];
        if i != 0 {
            chunk |= 0x80;
        }
        written += buf.put_u8(chunk)?;
    }
    Ok(written)
}

/// Validate that the next tag in `buf` matches `expected` (consuming it).
pub fn validate_tag(buf: &mut Reader<'_>, expected: &Tag) -> Result<()> {
    let tag = get_tag(buf)?;
    if tag.number != expected.number {
        return Err(Error::TagNumber {
            expected: expected.number,
            actual: tag.number,
        });
    }
    if tag.class != expected.class {
        return Err(Error::TagClass {
            expected: expected.class,
            actual: tag.class,
        });
    }
    Ok(())
}