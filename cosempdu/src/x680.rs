//! ASN.1 tag primitives (X.680).
//!
//! Mirrors `src/COSEMpdu/x680.py` for the tag metadata (classes, numbers,
//! names) shared by the concrete codecs (`x690`, `acse`). The abstract
//! `Value` types and constraint specifications are deliberately not modeled
//! here: the DLMS/COSEM PDUs are represented by their own concrete types.

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
    pub fn number(self) -> u64 {
        self as u64
    }

    /// Look up a universal tag by number.
    pub fn from_number(n: u64) -> Option<Self> {
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
    pub number: u64,
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
    pub fn context(number: u64) -> Self {
        Tag {
            class: Class::Context,
            number,
            constructed: false,
        }
    }

    /// Create an application tag.
    pub fn application(number: u64) -> Self {
        Tag {
            class: Class::Application,
            number,
            constructed: false,
        }
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