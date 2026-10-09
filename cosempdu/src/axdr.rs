//! A-XDR encoding primitives (IEC 61334-6:2000).
//!
//! Mirrors `src/COSEMpdu/axdr.py`. A-XDR omits the BER tag/length overhead for
//! types whose shape is already known from the schema; only variable-length
//! aggregates carry a length prefix (encoded as a variable-length integer).

use bytebuffer::{ByteBuffer, Reader};
use crate::error::{Error, Result};

/// Decode a variable-length integer (IEC 61334-6 §6.1.2).
///
/// Short form (0-127) occupies a single octet; long form uses a length octet
/// (bit 8 set, bits 7-1 = number of value octets) followed by big-endian bytes.
pub fn get_length(buf: &mut Reader<'_>) -> Result<usize> {
    let first = buf.get_u8()?;
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    let num_bytes = usize::from(first & 0x7F);
    if num_bytes == 0 {
        return Err(Error::Message(
            "invalid variable-length integer encoding",
        ));
    }
    Ok(buf.get_uint(num_bytes)? as usize)
}

/// Encode a variable-length integer (IEC 61334-6 §6.1.2).
pub fn put_length(buf: &mut ByteBuffer<'_>, value: usize) -> Result<usize> {
    if value <= 0x7F {
        return Ok(buf.put_u8(value as u8)?);
    }
    let bits = 64 - (value as u64).leading_zeros();
    let num_bytes = ((bits + 7) / 8) as usize;
    let mut written = buf.put_u8(0x80 | num_bytes as u8)?;
    let be = (value as u64).to_be_bytes();
    written += buf.write(&be[be.len() - num_bytes..])?;
    Ok(written)
}

/// Decode a length-prefixed OCTET STRING (IEC 61334-6 §6.3), borrowing the
/// bytes directly from the input buffer (zero-copy).
pub fn get_octet_string<'a>(buf: &mut Reader<'a>) -> Result<&'a [u8]> {
    let length = get_length(buf)?;
    Ok(buf.read(length)?)
}

/// Encode a length-prefixed OCTET STRING (IEC 61334-6 §6.3).
pub fn put_octet_string(buf: &mut ByteBuffer<'_>, value: &[u8]) -> Result<usize> {
    let mut written = put_length(buf, value.len())?;
    written += buf.write(value)?;
    Ok(written)
}

/// Decode a length-prefixed visible/UTF-8 string, borrowing it from the input
/// buffer (zero-copy).
pub fn get_string<'a>(buf: &mut Reader<'a>) -> Result<&'a str> {
    let bytes = get_octet_string(buf)?;
    core::str::from_utf8(bytes).map_err(|e| Error::InvalidUtf8 {
        valid_up_to: e.valid_up_to(),
    })
}

/// Encode a length-prefixed string (ASCII/UTF-8 bytes).
pub fn put_string(buf: &mut ByteBuffer<'_>, value: &str) -> Result<usize> {
    put_octet_string(buf, value.as_bytes())
}

/// Decode a variable-length BIT STRING, returning the packed octets and the
/// number of significant bits (IEC 61334-6 §6.4). The returned bytes are
/// borrowed from the input buffer (zero-copy).
pub fn get_bit_string<'a>(buf: &mut Reader<'a>) -> Result<(&'a [u8], usize)> {
    let num_bits = get_length(buf)?;
    let num_octets = (num_bits + 7) / 8;
    let bytes = buf.read(num_octets)?;
    Ok((bytes, num_bits))
}

/// Encode a variable-length BIT STRING from packed octets plus the number of
/// significant bits.
pub fn put_bit_string(buf: &mut ByteBuffer<'_>, bytes: &[u8], bit_len: usize) -> Result<usize> {
    let mut written = put_length(buf, bit_len)?;
    let num_octets = (bit_len + 7) / 8;
    written += buf.write(&bytes[..num_octets])?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_short_form_roundtrip() {
        for v in [0usize, 1, 127] {
            let mut backing = [0u8; 8];
            let written = {
                let mut buf = ByteBuffer::new(&mut backing);
                put_length(&mut buf, v).unwrap();
                buf.pos()
            };
            let mut r = Reader::new(&backing[..written]);
            assert_eq!(get_length(&mut r).unwrap(), v, "value {v}");
        }
    }

    #[test]
    fn length_long_form_roundtrip() {
        for v in [128usize, 255, 256, 65535, 65536, 1_000_000] {
            let mut backing = [0u8; 8];
            let written = {
                let mut buf = ByteBuffer::new(&mut backing);
                put_length(&mut buf, v).unwrap();
                buf.pos()
            };
            let mut r = Reader::new(&backing[..written]);
            assert_eq!(get_length(&mut r).unwrap(), v, "value {v}");
        }
    }

    #[test]
    fn octet_string_roundtrip() {
        let mut backing = [0u8; 16];
        let written = {
            let mut buf = ByteBuffer::new(&mut backing);
            put_octet_string(&mut buf, &[1, 2, 3]).unwrap();
            buf.pos()
        };
        let mut r = Reader::new(&backing[..written]);
        assert_eq!(get_octet_string(&mut r).unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn bit_string_roundtrip() {
        // 10 bits: 1010101010 -> packed 0xAA 0x40 (2 unused bits in last octet)
        let bytes = [0xAA, 0x40];
        let mut backing = [0u8; 16];
        let written = {
            let mut buf = ByteBuffer::new(&mut backing);
            put_bit_string(&mut buf, &bytes, 10).unwrap();
            buf.pos()
        };
        let mut r = Reader::new(&backing[..written]);
        let (out, len) = get_bit_string(&mut r).unwrap();
        assert_eq!(out, &bytes);
        assert_eq!(len, 10);
    }
}