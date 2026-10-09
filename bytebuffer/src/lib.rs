#![cfg_attr(not(feature = "std"), no_std)]

//! Byte buffer (heap-free, zero-copy) over a caller-owned slice.
//!
//! A single [`ByteBuffer`] supports both reading (decode) and writing (encode)
//! into a `&mut [u8]` slice, tracking an internal cursor. It never allocates:
//! the underlying bytes are owned by the caller (stack array, `static`,
//! `heapless::Vec`, DMA buffer, etc.).
//!
//! This crate is `no_std`-compatible by default. Enabling the `std` feature
//! additionally implements [`std::error::Error`] for [`Error`].

#[cfg(test)]
extern crate std;

/// Errors produced by byte-buffer operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Cursor moved past the end of the buffer.
    PositionOutOfRange { index: usize },

    /// Cursor shift moved outside the buffer bounds.
    ShiftOutOfRange { shift: isize },

    /// Not enough bytes remaining to satisfy a read or write.
    NotEnoughSpace { needed: usize },

    /// Input larger than the fixed-size decode buffer.
    InputTooLarge { len: usize, max: usize },
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
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Convenience result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Mutable byte buffer over a caller-provided slice (no allocation).
///
/// Supports both sequential reading (advancing the cursor) and writing.
#[derive(Debug)]
    pub struct ByteBuffer<'a> {
        data: &'a mut [u8],
        pos: usize,
    }

impl<'a> ByteBuffer<'a> {
    /// Wrap a mutable byte slice for reading and writing.
    pub fn new(data: &'a mut [u8]) -> Self {
        ByteBuffer { data, pos: 0 }
    }

    /// Length of the underlying buffer.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Raw byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.data
    }

    /// Mutable byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.data
    }

    /// Bytes consumed so far (start..pos).
    pub fn extract(&self) -> &[u8] {
        &self.data[..self.pos]
    }

    /// Current position.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Set position (bounds-checked). Returns the delta applied.
    pub fn set_pos(&mut self, index: usize) -> Result<isize> {
        if index > self.data.len() {
            return Err(Error::PositionOutOfRange { index });
        }
        let delta = index as isize - self.pos as isize;
        self.pos = index;
        Ok(delta)
    }

    /// Shift position by `value` (may be negative). Returns the delta applied.
    pub fn shift_pos(&mut self, value: isize) -> Result<isize> {
        let new = self.pos as isize + value;
        if new < 0 || new as usize > self.data.len() {
            return Err(Error::ShiftOutOfRange { shift: value });
        }
        self.pos = new as usize;
        Ok(value)
    }

    /// Number of bytes remaining from the given position.
    pub fn remaining(&self, pos: Option<usize>) -> usize {
        let pos = pos.unwrap_or(self.pos);
        self.data.len().saturating_sub(pos)
    }

    fn check_space(&self, space: usize, pos: Option<usize>) -> Result<()> {
        if self.remaining(pos) < space {
            return Err(Error::NotEnoughSpace { needed: space });
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Writing
    // -----------------------------------------------------------------------

    /// Write bytes at the current position and advance.
    pub fn write(&mut self, value: &[u8]) -> Result<usize> {
        self.check_space(value.len(), None)?;
        let pos = self.pos;
        self.data[pos..pos + value.len()].copy_from_slice(value);
        self.pos += value.len();
        Ok(value.len())
    }

    /// Write bytes at absolute `pos` (no advance).
    pub fn write_at(&mut self, value: &[u8], pos: usize) -> Result<usize> {
        self.check_space(value.len(), Some(pos))?;
        self.data[pos..pos + value.len()].copy_from_slice(value);
        Ok(value.len())
    }

    /// Shift `len` bytes from `from` to `to` within the buffer (memmove).
    ///
    /// Overlapping ranges are handled correctly (like `memmove`). Used by the
    /// BER encoder to make room for a long-form length prefix.
    pub fn shift(&mut self, from: usize, to: usize, len: usize) -> Result<()> {
        if from + len > self.data.len() || to + len > self.data.len() {
            return Err(Error::NotEnoughSpace {
                needed: from.max(to) + len,
            });
        }
        self.data.copy_within(from..from + len, to);
        Ok(())
    }

    /// Write a single byte and advance.
    pub fn put_u8(&mut self, value: u8) -> Result<usize> {
        self.check_space(1, None)?;
        self.data[self.pos] = value;
        self.pos += 1;
        Ok(1)
    }

    // -----------------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------------

    /// Read a single unsigned byte and advance.
    pub fn get_u8(&mut self) -> Result<u8> {
        self.check_space(1, None)?;
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Read a big-endian unsigned integer of `length` bytes, advancing.
    pub fn get_uint(&mut self, length: usize) -> Result<u64> {
        let pos = self.pos;
        let v = self.get_uint_at(pos, length)?;
        self.pos = pos + length;
        Ok(v)
    }

    /// Read a big-endian unsigned integer at `pos` (no advance).
    pub fn get_uint_at(&self, pos: usize, length: usize) -> Result<u64> {
        let bytes = self.read_at(pos, length)?;
        let mut value: u64 = 0;
        for b in bytes {
            value = (value << 8) | u64::from(*b);
        }
        Ok(value)
    }

    /// Read `length` bytes at the current position and advance (borrowed slice).
    pub fn read(&mut self, length: usize) -> Result<&[u8]> {
        self.check_space(length, None)?;
        let pos = self.pos;
        let out = &self.data[pos..pos + length];
        self.pos = pos + length;
        Ok(out)
    }

    /// Read `length` bytes at absolute `pos` without advancing.
    pub fn read_at(&self, pos: usize, length: usize) -> Result<&[u8]> {
        self.check_space(length, Some(pos))?;
        Ok(&self.data[pos..pos + length])
    }

    /// Peek `length` bytes at the current position without advancing.
    pub fn peek(&self, length: usize) -> Result<&[u8]> {
        self.read_at(self.pos, length)
    }
}

impl<'a> core::fmt::Display for ByteBuffer<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ByteBuffer[{}]: pos={}", self.len(), self.pos)
    }
}

impl<'a> core::ops::Index<usize> for ByteBuffer<'a> {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        &self.data[index]
    }
}

/// Immutable, zero-copy reader over a caller-provided byte slice.
///
/// Unlike [`ByteBuffer`], a `Reader` only reads (it never writes). Because it
/// holds a shared `&'a [u8]`, every read returns a `&'a [u8]` sub-slice that
/// borrows the original data for its full lifetime `'a` - enabling zero-copy
/// decoding where decoded values reference the input buffer directly.
#[derive(Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice for zero-copy reading.
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Length of the underlying buffer.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the underlying buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The full borrowed byte slice.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Current read position.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Set position (bounds-checked). Returns the delta applied.
    pub fn set_pos(&mut self, index: usize) -> Result<isize> {
        if index > self.data.len() {
            return Err(Error::PositionOutOfRange { index });
        }
        let delta = index as isize - self.pos as isize;
        self.pos = index;
        Ok(delta)
    }

    /// Shift position by `value` (may be negative). Returns the delta applied.
    pub fn shift_pos(&mut self, value: isize) -> Result<isize> {
        let new = self.pos as isize + value;
        if new < 0 || new as usize > self.data.len() {
            return Err(Error::ShiftOutOfRange { shift: value });
        }
        self.pos = new as usize;
        Ok(value)
    }

    /// Number of bytes remaining from the given position.
    pub fn remaining(&self, pos: Option<usize>) -> usize {
        let pos = pos.unwrap_or(self.pos);
        self.data.len().saturating_sub(pos)
    }

    /// Remaining bytes as a borrowed slice (does not advance).
    pub fn remaining_bytes(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn check_space(&self, space: usize, pos: Option<usize>) -> Result<()> {
        if self.remaining(pos) < space {
            return Err(Error::NotEnoughSpace { needed: space });
        }
        Ok(())
    }

    /// Read a single unsigned byte and advance.
    pub fn get_u8(&mut self) -> Result<u8> {
        self.check_space(1, None)?;
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Read a big-endian unsigned integer of `length` bytes, advancing.
    pub fn get_uint(&mut self, length: usize) -> Result<u64> {
        let pos = self.pos;
        let v = self.get_uint_at(pos, length)?;
        self.pos = pos + length;
        Ok(v)
    }

    /// Read a big-endian unsigned integer at `pos` (no advance).
    pub fn get_uint_at(&self, pos: usize, length: usize) -> Result<u64> {
        let bytes = self.read_at(pos, length)?;
        let mut value: u64 = 0;
        for b in bytes {
            value = (value << 8) | u64::from(*b);
        }
        Ok(value)
    }

    /// Read `length` bytes at the current position and advance, returning a
    /// slice that borrows the underlying data for its full lifetime `'a`.
    pub fn read(&mut self, length: usize) -> Result<&'a [u8]> {
        self.check_space(length, None)?;
        let data: &'a [u8] = self.data;
        let start = self.pos;
        self.pos = start + length;
        Ok(&data[start..start + length])
    }

    /// Read `length` bytes at absolute `pos` without advancing.
    pub fn read_at(&self, pos: usize, length: usize) -> Result<&'a [u8]> {
        self.check_space(length, Some(pos))?;
        let data: &'a [u8] = self.data;
        Ok(&data[pos..pos + length])
    }

    /// Peek `length` bytes at the current position without advancing.
    pub fn peek(&self, length: usize) -> Result<&'a [u8]> {
        self.read_at(self.pos, length)
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteBuffer, Reader};

    #[test]
    fn write_then_read_roundtrip() {
        let mut backing = [0u8; 10];
        let mut buf = ByteBuffer::new(&mut backing);
        assert_eq!(buf.write(&[1, 2, 3]).unwrap(), 3);
        assert_eq!(buf.pos(), 3);
        assert_eq!(buf.extract(), &[1, 2, 3]);
        buf.set_pos(0).unwrap();
        assert_eq!(buf.get_u8().unwrap(), 0x01);
        assert_eq!(buf.get_u8().unwrap(), 0x02);
        assert_eq!(buf.pos(), 2);
    }

    #[test]
    fn read_borrowed_slice() {
        let mut backing = [0x0F, 0x1B, 0x2C];
        let mut buf = ByteBuffer::new(&mut backing);
        assert_eq!(buf.read(2).unwrap(), &[0x0F, 0x1B]);
        assert_eq!(buf.pos(), 2);
    }

    #[test]
    fn reader_zero_copy_lifetime() {
        let input = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut r = Reader::new(&input);
        let s = r.read(3).unwrap();
        assert_eq!(s, &[0xAA, 0xBB, 0xCC]);
        drop(r);
        assert_eq!(s, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn reader_read_and_uint() {
        let input = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut r = Reader::new(&input);
        assert_eq!(r.get_u8().unwrap(), 0x01);
        assert_eq!(r.get_uint(2).unwrap(), 0x0203);
        assert_eq!(r.peek(1).unwrap(), &[0x04]);
        assert_eq!(r.read(2).unwrap(), &[0x04, 0x05]);
    }

    #[test]
    fn shift_memmove() {
        let mut backing = [1u8, 2, 3, 4, 5, 0, 0, 0];
        {
            let mut buf = ByteBuffer::new(&mut backing);
            buf.shift(0, 2, 5).unwrap();
        }
        assert_eq!(&backing, &[1, 2, 1, 2, 3, 4, 5, 0]);
    }
}
