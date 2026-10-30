//! BER codec (X.690 §8) low-level, allocation-free primitives.
//!
//! Mirrors the encoding primitives of `src/COSEMpdu/ber.py` needed by the
//! concrete DLMS/COSEM codecs (the ACSE APDUs). Unlike the Python module —
//! which expresses every concrete BER type as a class — here only the
//! low-level primitives are provided:
//!
//! * [`put_tlv`] — write a tag + length + content triple.
//! * [`with_content`] — write a tag + length prefix, invoke a closure for the
//!   content, then backfill the length.
//! * [`put_signed`] / [`decode_signed`] — minimal two's-complement INTEGER
//!   content.

use bytebuffer::ByteBuffer;
use crate::error::{Error, Result};
use crate::x680::Tag;
use crate::x690::{Length};

// ---------------------------------------------------------------------------
// Low-level byte helpers (tag/length encoding into plain vectors)
// ---------------------------------------------------------------------------

/// Build a full TLV encoding (tag + length + content) directly into the buffer.
pub fn put_tlv(buf: &mut ByteBuffer<'_>, tag: &Tag, content: &[u8]) -> Result<usize> {
    let mut written = tag.put(buf)?;
    written += Length::new(content.len() as i64)?.put(buf)?;
    written += buf.write(content)?;
    Ok(written)
}

// ---------------------------------------------------------------------------
// Content encoders / decoders
// ---------------------------------------------------------------------------

/// Minimal signed two's-complement encoding of an integer (X.690 §8.3.3).
pub fn put_signed(buf: &mut ByteBuffer<'_>, value: i64) -> Result<usize> {
    if value == 0 {
        return Ok(buf.put_u8(0x00)?);
    }
    let v = value as i128;
    let abs = v.unsigned_abs();
    let bits = 128 - abs.leading_zeros();
    let num_bytes = (((bits + 1 + 7) / 8) as usize).max(1);
    let be = v.to_be_bytes();
    Ok(buf.write(&be[16 - num_bytes..])?)
}

pub fn put_u8(buf: &mut ByteBuffer<'_>, value: u8) -> Result<usize> {
    Ok(buf.put_u8(value)?)
}

/// Decode big-endian two's-complement content octets into an `i64`.
pub fn decode_signed(content: &[u8]) -> Result<i64> {
    if content.is_empty() {
        return Err(Error::IntegerEmpty);
    }
    if content.len() > 8 {
        return Err(Error::IntegerTooWide { len: content.len() });
    }
    let sign = if content[0] & 0x80 != 0 { 0xFF } else { 0x00 };
    let mut buf = [sign; 8];
    buf[8 - content.len()..].copy_from_slice(content);
    Ok(i64::from_be_bytes(buf))
}

/// Decode big-endian two's-complement content octets into an `u8`.
pub fn decode_u8(content: &[u8]) -> Result<u8> {
    if content.is_empty() {
        return Err(Error::IntegerEmpty);
    }
    if content.len() != 1 {
        return Err(Error::IntegerTooWide { len: content.len() });
    }
    Ok(content[0])
}

/// Write a tag + length prefix, invoke `f` to write the content into the
/// reserved region, then backfill the length (X.690 §8.1.3).
///
/// A single length octet is reserved up front; if the content exceeds 127
/// bytes, the content is shifted right and a long-form length is backfilled.
pub fn with_content(
    buf: &mut ByteBuffer<'_>,
    tag: &Tag,
    f: impl FnOnce(&mut ByteBuffer<'_>) -> Result<usize>,
) -> Result<usize> {
    let start = buf.pos();
    let tag_len = tag.put(buf)?;
    buf.put_u8(0)?; // placeholder length octet
    let content_start = buf.pos();
    let content_len = f(buf)?;
    if content_len < 0x80 {
        buf.write_at(&[content_len as u8], start + tag_len)?;
    } else {
        let be = (content_len as u64).to_be_bytes();
        let n = be.iter().position(|&b| b != 0).map(|p| 8 - p).unwrap_or(1);
        buf.shift(content_start, content_start + n, content_len)?;
        buf.write_at(&[0x80 | n as u8], start + tag_len)?;
        buf.write_at(&be[8 - n..], start + tag_len + 1)?;
        buf.set_pos(content_start + content_len + n)?;
    }
    Ok(buf.pos() - start)
}

