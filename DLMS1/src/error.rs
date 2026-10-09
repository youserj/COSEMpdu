//! Error and `Result` types for the DLMS1 crate.

use core::fmt;

/// Errors produced by OBIS and COSEM interface-class operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The value's A-XDR tag does not match the expected type.
    TypeMismatch { expected: u8, got: u8 },
    /// The value's A-XDR tag is not in the allowed CHOICE set.
    ChoiceMismatch { got: u8 },
    /// Invalid OBIS code / logical name.
    InvalidObis,
    /// Underlying COSEM codec error (structure validation).
    Codec(cosempdu::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TypeMismatch { expected, got } => {
                write!(f, "type mismatch: expected tag {expected}, got {got}")
            }
            Error::ChoiceMismatch { got } => {
                write!(f, "value tag {got} is not in the allowed CHOICE set")
            }
            Error::InvalidObis => write!(f, "invalid OBIS code"),
            Error::Codec(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<cosempdu::Error> for Error {
    fn from(e: cosempdu::Error) -> Self {
        Error::Codec(e)
    }
}

/// Convenience result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;
