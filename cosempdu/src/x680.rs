//! ASN.1 tag primitives (X.680).
//!
//! Mirrors `src/COSEMpdu/x680.py` for the tag metadata (classes, numbers,
//! names) shared by the concrete codecs (`x690`, `acse`). The abstract
//! `Value` types and constraint specifications are deliberately not modeled
//! here: the DLMS/COSEM PDUs are represented by their own concrete types.

use crate::{Result};
use bytebuffer::{Reader, ByteBuffer};

/// Universal tag class number (X.680 Table 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UniversalTag {
    Boolean = 1,
    Integer = 2,
    BitString = 3,
    OctetString = 4,
    Null = 5,
    ObjectIdentifier = 6,
    Real = 9,
    Enumerated = 10,
    Utf8String = 12,
    Sequence = 16,
    Set = 17,
    VisibleString = 26,
    GeneralizedTime = 24,
    UtcTime = 23,
}

impl UniversalTag {
    /// Tag number as a raw `u64`.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// Look up a universal tag by number.
    pub fn from_number(n: u8) -> Option<Self> {
        use UniversalTag::*;
        Some(match n {
            1 => Boolean,
            2 => Integer,
            3 => BitString,
            4 => OctetString,
            5 => Null,
            6 => ObjectIdentifier,
            9 => Real,
            10 => Enumerated,
            12 => Utf8String,
            16 => Sequence,
            17 => Set,
            23 => UtcTime,
            24 => GeneralizedTime,
            26 => VisibleString,
            _ => return None,
        })
    }
}

/// Tag class (X.680 §8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Universal = 0,
    Application = 1,
    Context = 2,
    Private = 3,
}

impl Class {

    /// Raw two-bit value used in the first tag octet.
    pub fn bits(self) -> u8 {
        match self {
            Class::Universal => 0x00,
            Class::Application => 0x40,
            Class::Context => 0x80,
            Class::Private => 0xC0,
        }
    }

    /// Parse from the two high bits of the first tag octet.
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0xC0 {
            0x40 => Class::Application,
            0x80 => Class::Context,
            0xC0 => Class::Private,
            _ => Class::Universal,
        }
    }
}

/// An ASN.1 tag (class + number + constructed flag metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag {
    pub class: Class,
    pub number: u8,
    pub constructed: bool,
}

impl Tag {
    /// Create a universal tag.
    pub fn universal(tag: UniversalTag) -> Self {
        Tag {
            class: Class::Universal,
            number: tag.number(),
            constructed: false,
        }
    }

    /// Create a context-specific tag.
    pub fn context(number: u8) -> Self {
        Tag {
            class: Class::Context,
            number,
            constructed: false,
        }
    }

    /// Create an application tag.
    pub fn application(number: u8) -> Self {
        Tag {
            class: Class::Application,
            number,
            constructed: false,
        }
    }

    /// Decode a BER tag (advancing the buffer) per X.690 §8.1.2.
    pub fn get(buf: &mut Reader<'_>) -> Result<Self> {
        let first = buf.get_u8()?;
        let class = Class::from_bits(first);
        let constructed = first & 0x20 != 0;
        let mut tag_number = first & 0x1F;
        if tag_number == 0x1F {
            // High-tag-number form (X.690 §8.1.2.4)
            tag_number = 0;
            loop {
                let byte = buf.get_u8()?;
                tag_number = (tag_number << 7) | (byte & 0x7F);
                if byte & 0x80 == 0 {
                    break;
                }
            }
        }
        Ok(Self {
            class,
            number: tag_number,
            constructed,
        })
    }

    /// Encode a BER tag (advancing the buffer) per X.690 §8.1.2.
    pub fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut initial = self.class.bits();
        if self.constructed {
            initial |= 0x20;
        }
        if self.number < 0x1F {
            return Ok(buf.put_u8(initial | self.number)?);
        }
        let mut written = buf.put_u8(initial | 0x1F)?;
        // Encode tag number in 7-bit chunks, MSB first, last chunk bit 8 = 0.
        let mut chunks = [0u8; 10];
        let mut count = 0usize;
        let mut n = self.number;
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


}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_encoding_bits() {
        let t = Tag::universal(UniversalTag::Integer);
        assert_eq!(t.class, Class::Universal);
        assert_eq!(t.number, 2);
    }
}