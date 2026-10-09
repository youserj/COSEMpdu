//! Error and Result types for the COSEM PDU library.
//!
//! Mirrors the Python `StructResult.result` semantics: every fallible
//! operation returns `Result<T, Error>` rather than panicking.
//!
//! `Error` is a zero-allocation, `Copy` type. Every variant carries only small
//! numeric fields and `&'static str` names, so constructing an error never
//! touches the heap and error reporting is infallible — suitable for `no_std`
//! embedded targets where no global allocator is available on the error path.

use crate::x680::Class;

/// Top-level error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    // ---------------------------------------------------------------------
    // Buffer / input size
    // ---------------------------------------------------------------------
    /// Cursor moved past the end of the buffer.
    PositionOutOfRange { index: usize },

    /// Cursor shift moved outside the buffer bounds.
    ShiftOutOfRange { shift: isize },

    /// Not enough bytes remaining to satisfy a read or write.
    NotEnoughSpace { needed: usize },

    /// Input larger than the fixed-size decode buffer.
    InputTooLarge { len: usize, max: usize },

    // ---------------------------------------------------------------------
    // Tag / class mismatches
    // ---------------------------------------------------------------------
    /// Decoded tag number does not match the expected one.
    TagNumber { expected: u64, actual: u64 },

    /// Decoded tag class does not match the expected one.
    TagClass { expected: Class, actual: Class },

    /// Expected a named APDU tag byte, got a different one.
    UnexpectedTag { name: &'static str, actual: u8 },

    /// Unrecognized discriminator within a CHOICE.
    UnknownChoice { name: &'static str, choice: u8 },

    /// Unrecognized top-level tag byte.
    UnknownTag { name: &'static str, tag: u8 },

    /// A universal tag number that this decoder does not implement.
    UnsupportedUniversalTag { number: u64 },

    /// Expected a universal-class tag, got another class.
    ExpectedUniversalClass { actual: Class },

    // ---------------------------------------------------------------------
    // Value / constraint validation
    // ---------------------------------------------------------------------
    /// A length value failed its constraint (X.690 §8.1.3).
    InvalidLength { value: i64 },

    /// An integer value fell outside its permitted range.
    ValueOutOfRange { value: i64, lower: i64, upper: i64 },

    /// An ACSE OBJECT IDENTIFIER did not conform to the DLMS/COSEM structure
    /// `{ 2 16 756 5 8 X Y }`.
    InvalidAcseOid,

    // ---------------------------------------------------------------------
    // BER content decoding
    // ---------------------------------------------------------------------
    /// INTEGER content was empty.
    IntegerEmpty,

    /// INTEGER content is too wide to fit in an `i64`.
    IntegerTooWide { len: usize },

    /// BIT STRING carried an invalid unused-bits count.
    InvalidUnusedBits { unused: u8 },

    // ---------------------------------------------------------------------
    // Unsupported operations / invalid data
    // ---------------------------------------------------------------------
    /// A type or operation that is not implemented.
    Unsupported { what: &'static str },

    /// Input bytes were not valid UTF-8.
    InvalidUtf8 { valid_up_to: usize },

    /// A message without any dynamic data.
    Message(&'static str),
}

/// Convenience result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// Construct an [`Error::Message`] from a static string.
    pub fn message(msg: &'static str) -> Self {
        Error::Message(msg)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::PositionOutOfRange { index } => {
                write!(f, "buffer position {index} out of range")
            }
            Error::ShiftOutOfRange { shift } => {
                write!(f, "buffer shift {shift} out of range")
            }
            Error::NotEnoughSpace { needed } => {
                write!(f, "not enough space: {needed} bytes needed")
            }
            Error::InputTooLarge { len, max } => {
                write!(f, "input too large: {len} bytes (maximum {max})")
            }
            Error::TagNumber { expected, actual } => {
                write!(f, "tag mismatch: expected number {expected}, got {actual}")
            }
            Error::TagClass { expected, actual } => {
                write!(f, "tag mismatch: expected class {expected:?}, got {actual:?}")
            }
            Error::UnexpectedTag { name, actual } => {
                write!(f, "expected {name}, got {actual}")
            }
            Error::UnknownChoice { name, choice } => {
                write!(f, "unknown {name} choice {choice}")
            }
            Error::UnknownTag { name, tag } => {
                write!(f, "unknown {name} tag {tag}")
            }
            Error::UnsupportedUniversalTag { number } => {
                write!(f, "unsupported universal tag {number}")
            }
            Error::ExpectedUniversalClass { actual } => {
                write!(f, "expected universal class, got {actual:?}")
            }
            Error::InvalidLength { value } => {
                write!(f, "invalid length value {value}")
            }
            Error::ValueOutOfRange { value, lower, upper } => {
                write!(f, "value {value} outside range ({lower}..{upper})")
            }
            Error::InvalidAcseOid => {
                write!(f, "invalid DLMS/COSEM ACSE OBJECT IDENTIFIER")
            }
            Error::IntegerEmpty => write!(f, "integer content is empty"),
            Error::IntegerTooWide { len } => {
                write!(f, "integer content of {len} bytes does not fit in i64")
            }
            Error::InvalidUnusedBits { unused } => {
                write!(f, "invalid unused bits count {unused}")
            }
            Error::Unsupported { what } => {
                write!(f, "unsupported operation: {what}")
            }
            Error::InvalidUtf8 { valid_up_to } => {
                write!(f, "invalid UTF-8: {valid_up_to} bytes parsed")
            }
            Error::Message(msg) => write!(f, "{msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<bytebuffer::Error> for Error {
    fn from(err: bytebuffer::Error) -> Self {
        match err {
            bytebuffer::Error::PositionOutOfRange { index } => {
                Error::PositionOutOfRange { index }
            }
            bytebuffer::Error::ShiftOutOfRange { shift } => {
                Error::ShiftOutOfRange { shift }
            }
            bytebuffer::Error::NotEnoughSpace { needed } => {
                Error::NotEnoughSpace { needed }
            }
            bytebuffer::Error::InputTooLarge { len, max } => {
                Error::InputTooLarge { len, max }
            }
        }
    }
}