//! X.690 BER length/tag primitives and ED (encode/decode) helpers.
//!
//! Mirrors `src/COSEMpdu/x690.py`: provides the [`Length`] component, tag
//! encoding/decoding, and the `ed2buf` / `ed2ed` / `recast` composition
//! helpers built on the [`ED`] trait.

use bytebuffer::{ByteBuffer, Reader};
use crate::error::{Error, Result};
use crate::x680::{Tag};

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

/// Validate that the next tag in `buf` matches `expected` (consuming it).
pub fn validate_tag(buf: &mut Reader<'_>, expected: &Tag) -> Result<()> {
    let tag = Tag::get(buf)?;
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