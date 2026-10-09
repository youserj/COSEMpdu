//! COSEM Interface Classes and the OBIS Object Identification System
//! (DLMS UA 1000-1 Ed. 14, the "Blue Book").
//!
//! This crate builds on [`cosempdu`] (which provides the COSEM [`Data`] type and
//! the A-XDR codec) and adds the two data-model layers defined by the Blue Book:
//!
//! - [`obis`] — the OBIS Object Identification System (clause 4): the 6-byte
//!   [`ObisCode`] `A.B.C.D.E.F`, its logical-name form, value-group enums and the
//!   short-name (SN) base-name mapping.
//! - [`ic`] — the COSEM interface classes (clause 7): the [`ClassId`] enumeration,
//!   the [`InterfaceClass`] trait and concrete class implementations.
//!
//! The crate is `no_std`-compatible (uses only `core`), mirroring `cosempdu`.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod error;
pub mod ic;
pub mod obis;

pub use error::{Error, Result};
pub use ic::{
    Attribute, AttributeInfo, AttributeKey, AttributeType, ClassId, Classifier,
    CommonDataType, InterfaceClass, Validator,
};
pub use obis::ObisCode;
