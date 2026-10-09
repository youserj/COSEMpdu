# Byte Buffer API

The `buffer` module provides a single heap-free [`ByteBuffer`] type that borrows a caller-owned `&mut [u8]` slice and supports both sequential reading (decode) and writing (encode), tracking an internal cursor. It never allocates: the underlying bytes are owned by the caller (stack array, `static`, `heapless::Vec`, DMA buffer, etc.).

All fallible operations return `cosempdu::Result<T>` (i.e. `Result<T, Error>`) rather than panicking.

---

## `ByteBuffer<'a>`

```rust
pub struct ByteBuffer<'a> {
    data: &'a mut [u8],
    pos: usize,
}
```

### Constructors

| Method | Description |
|--------|-------------|
| `new(data: &'a mut [u8]) -> Self` | Wrap a mutable slice for reading and writing |

### Reading (decode)

| Method | Description |
|--------|-------------|
| `get_u8() -> Result<u8>` | Read one byte and advance |
| `get() -> Result<u8>` | Alias for `get_u8` |
| `get_uint(length) -> Result<u64>` | Read a big-endian unsigned integer, advancing |
| `get_uint_at(pos, length) -> Result<u64>` | Read a big-endian integer at `pos` (no advance) |
| `read(length) -> Result<&[u8]>` | Read `length` bytes and advance (borrowed slice) |
| `read_at(pos, length) -> Result<&[u8]>` | Read `length` bytes at `pos` (no advance, borrowed) |
| `peek(length) -> Result<&[u8]>` | Peek `length` bytes without advancing |

### Writing (encode)

| Method | Description |
|--------|-------------|
| `write(value: &[u8]) -> Result<usize>` | Write bytes at the current position and advance |
| `write_at(value, pos) -> Result<usize>` | Write bytes at absolute `pos` (no advance) |
| `put_u8(value: u8) -> Result<usize>` | Write a single byte and advance |

### Position / Access

| Method | Description |
|--------|-------------|
| `len() -> usize` | Length of the underlying slice |
| `is_empty() -> bool` | Whether the slice is empty |
| `pos() -> usize` | Current position |
| `set_pos(index) -> Result<isize>` | Set position (bounds-checked); returns the delta |
| `shift_pos(value) -> Result<isize>` | Shift position by `value` (may be negative) |
| `remaining(pos) -> usize` | Bytes remaining from `pos` (defaults to current) |
| `as_bytes() -> &[u8]` | Raw byte slice |
| `as_bytes_mut() -> &mut [u8]` | Mutable byte slice |
| `extract() -> &[u8]` | Bytes written/consumed so far (start..pos) |

---

## Decoding from an immutable slice

`ByteBuffer` borrows a `&mut [u8]`; to decode from immutable input (e.g. a `&[u8]` received from a socket), copy it into a mutable buffer first:

```rust
let data: &[u8] = &[0x60, 0x03, 0x01, 0x02, 0x03];
let mut backing = [0u8; 4096];
backing[..data.len()].copy_from_slice(data);
let mut buf = ByteBuffer::new(&mut backing[..data.len()]);
// ... decode from `buf` ...
```

---

## Usage Examples

```rust
use cosempdu::buffer::ByteBuffer;

// === Writing (encode) ===
let mut backing = [0u8; 64];
let mut buf = ByteBuffer::new(&mut backing);
buf.write(b"Hello")?;    // position = 5
buf.put_u8(0x20)?;       // position = 6
let written = buf.extract(); // &[0..6]

// === Reading (decode) ===
buf.set_pos(0)?;
assert_eq!(buf.get_u8()?, b'H');
assert_eq!(buf.get_u8()?, b'e');
```