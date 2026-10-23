# Data — COSEM Data Types (IEC 62056-6-2)

## Overview

The `data` module implements COSEM Data types according to the IEC 62056-6-2 (DLMS/COSEM) standard. These types are used to represent attribute values, read and write results in the COSEM protocol. All types are encoded using A-XDR (`axdr.rs`).

The module is central to:
- **COSEM APDU** (`apdu.rs`) — all APDU messages use `Data` values
- **CompactArray** — compact array storage (`Data::CompactArray`)

- [X.680](x680.md)
- [AXDR](axdr.md)
- [APDU](apdu.md)

## Module Contents

### The `Data` Enum (CHOICE)

`Data` is a single Rust enum that carries every COSEM base data type. Each variant maps to the implicit tag number used by A-XDR (IEC 61334-6 §6.6).

| Variant | Tag | ASN.1 Type | Description |
|---------|-----|------------|-------------|
| `NullData` | 0 | NULL | null-data |
| `Array(&[Data])` | 1 | SEQUENCE OF Data | Data array |
| `Structure(&[Data])` | 2 | SEQUENCE OF Data | Structure (fields in order) |
| `Boolean(bool)` | 3 | BOOLEAN | Boolean value |
| `BitString { bytes, bit_len }` | 4 | BIT STRING | Bit string |
| `DoubleLong(i32)` | 5 | Integer32 | 32-bit signed |
| `DoubleLongUnsigned(u32)` | 6 | Unsigned32 | 32-bit unsigned |
| `OctetString(&[u8])` | 9 | OCTET STRING | Byte string |
| `VisibleString(&str)` | 10 | VisibleString | ASCII string |
| `Utf8String(&str)` | 12 | UTF8String | UTF-8 string |
| `Bcd(i8)` | 13 | Integer8 | BCD value |
| `Integer(i8)` | 15 | Integer8 | 8-bit signed |
| `Long(i16)` | 16 | Integer16 | 16-bit signed |
| `Unsigned(u8)` | 17 | Unsigned8 | 8-bit unsigned |
| `LongUnsigned(u16)` | 18 | Unsigned16 | 16-bit unsigned |
| `CompactArray { … }` | 19 | SEQUENCE | Compact array |
| `Long64(i64)` | 20 | Integer64 | 64-bit signed |
| `Long64Unsigned(u64)` | 21 | Unsigned64 | 64-bit unsigned |
| `Enum(u8)` | 22 | Unsigned8 | Enumeration |
| `Float32(f32)` | 23 | OCTET STRING SIZE(4) | 32-bit IEEE 754 |
| `Float64(f64)` | 24 | OCTET STRING SIZE(8) | 64-bit IEEE 754 |
| `DateTime([u8; 12])` | 25 | OCTET STRING SIZE(12) | Date and time |
| `Date([u8; 5])` | 26 | OCTET STRING SIZE(5) | Date |
| `Time([u8; 4])` | 27 | OCTET STRING SIZE(4) | Time |
| `DeltaInteger(i8)` | 28 | Integer8 | delta-integer |
| `DeltaLong(i16)` | 29 | Integer16 | delta-long |
| `DeltaDoubleLong(i32)` | 30 | Integer32 | delta-double-long |
| `DeltaUnsigned(u8)` | 31 | Unsigned8 | delta-unsigned |
| `DeltaLongUnsigned(u16)` | 32 | Unsigned16 | delta-long-unsigned |
| `DeltaDoubleLongUnsigned(u32)` | 33 | Unsigned32 | delta-double-long-unsigned |
| `DontCare` | 255 | NULL | dont-care |

### `CompactArray`

The `CompactArray` variant stores `contents_description: u8` and `array_contents: &[u8]` — the contents-description byte followed by a length-prefixed octet string of packed array contents.

### Methods

| Method | Description |
|--------|-------------|
| `tag()` | The A-XDR implicit tag number for this value |
| `put(buf)` | Encode tag + content (A-XDR CHOICE alternative) |
| `put_lc(buf)` | Encode content only (no tag) |
| `get(buf, arena)` | Decode tag + content |
| `get_lc(buf, arena, tag)` | Decode content for a known tag |

### The `Arena` Bump Allocator

Decoding a nested `Array`/`Structure` needs somewhere to hold the decoded
`Data` elements. Because `Data<'a>` borrows (`Array(&'a [Data<'a>])`,
`Structure(&'a [Data<'a>])`), those elements must live for `'a` — and the
library does it without heap allocation, using a caller-provided backing slice
and a bump pointer:

```rust
pub struct Arena<'a, T> {
    storage: &'a mut [core::mem::MaybeUninit<T>], // caller-owned backing
    len: usize,                                    // slots already handed out
}
```

| Method | Description |
|--------|-------------|
| `Arena::new(&mut [MaybeUninit<T>])` | Wrap a caller-owned backing slice |
| `len()` / `is_empty()` | Number of slots currently allocated |
| `alloc(n)` | Reserve `n` slots, return `&'a mut [MaybeUninit<T>]`; error on overflow |

**How it works.** `alloc(n)` bumps `len` by `n` and returns the disjoint sub-slice
`storage[start..start+n)`. `decode_data` then fills those uninitialized slots by
calling `Data::get` for each element and exposes them as an initialized
`&'a [Data<'a>]`:

```rust
pub fn decode_data<'a>(
    buf: &mut Reader<'a>,
    arena: &mut Arena<'a, Data<'a>>,
    n: usize,
) -> Result<&'a [Data<'a>]>
```

**Self-referential.** The arena is self-referential: a decoded `Data` may contain
`&'a [Data<'a>]` references pointing back into this same backing slice. So the
backing must outlive every decoded `Data`, and slots are written once during a
single decode pass and read afterwards.

**Safety.** This is the one place the library uses `unsafe`, in two blocks:

- `alloc` builds the mutable slice with `from_raw_parts_mut`. It is sound because
  the pointer stays inside `storage` (which lives for `'a`) and `[start, start+n)`
  is disjoint from every previously returned slice — `len` only ever advances.
- `decode_data` writes each decoded `Data` into a reserved slot exactly once
  (`ptr.add(i).write(item)`), then re-borrows the now-initialized range as
  `&'a [Data<'a>]`.

**Usage.**

```rust
use cosempdu::buffer::Reader;
use cosempdu::data::{Arena, Data};

// Array([Unsigned(200), Boolean(true)]): a nested array that needs an arena.
let backing = [1, 2, 17, 0xC8, 3, 0xFF];
let mut reader = Reader::new(&backing);

let mut arena_storage = [core::mem::MaybeUninit::uninit(); 16];
let mut arena = Arena::new(&mut arena_storage);

let data = Data::get(&mut reader, &mut arena)?;
if let Data::Array(items) = data {
    assert_eq!(items.len(), 2);
}
```

**Contract / limitations.**

- Fixed capacity: the caller sizes `arena_storage`; overflow returns
  `Error::Message("arena overflow")` (no allocation).
- Self-referential: don't move `arena`/`arena_storage` while decoded `Data`
  borrows are alive, and don't reuse slots after they have been read.
- The same pattern powers `apdu.rs`: `DecodeContext` bundles several arenas to
  decode APDU fields together with their nested `Data`.

## Usage

### Reading a COSEM Value

```rust
use cosempdu::buffer::Reader;
use cosempdu::data::{Arena, Data};

let backing = [17, 0xC8]; // Unsigned(200): tag 17 + value 0xC8
let mut reader = Reader::new(&backing);
let mut arena_storage = [core::mem::MaybeUninit::uninit(); 16];
let mut arena = Arena::new(&mut arena_storage);
let data = Data::get(&mut reader, &mut arena)?;
assert_eq!(data, Data::Unsigned(200));
```

### Creating Values

```rust
use cosempdu::data::Data;

let voltage = Data::DoubleLongUnsigned(230000); // 230.000 V
let serial = Data::OctetString(b"12345678");
let flag = Data::Boolean(true);
```

### Composite Values (Array / Structure)

```rust
use cosempdu::buffer::{ByteBuffer, Reader};
use cosempdu::data::{Arena, Data};

let record = Data::Array(&[
    Data::Integer(42),
    Data::VisibleString("hello"),
    Data::Boolean(true),
]);
let mut backing = [0u8; 4096];
let mut buf = ByteBuffer::new(&mut backing);
record.put(&mut buf)?;

let mut arena_storage = [core::mem::MaybeUninit::uninit(); 16];
let mut arena = Arena::new(&mut arena_storage);
let mut reader = Reader::new(&backing[..buf.pos()]);
assert_eq!(Data::get(&mut reader, &mut arena)?, record);
```

### Known Encodings

```rust
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::Data;

fn encode(d: &Data) -> Vec<u8> {
    let mut backing = [0u8; 4096];
    let mut buf = ByteBuffer::new(&mut backing);
    d.put(&mut buf).unwrap();
    buf.extract().to_vec()
}

assert_eq!(encode(&Data::Unsigned(200)), vec![17, 0xC8]);
assert_eq!(encode(&Data::Boolean(true)), vec![3, 0xFF]);
assert_eq!(encode(&Data::NullData), vec![0]);
```

### A Concrete Structure: `Codec` + `FromStructure`

A generic [`Data::Structure`] can be narrowed to a concrete, typed structure via
two complementary traits:

- **`Codec`** — the common object-safe encode/decode interface:
  `put` (encode), `assign` (decode a [`Data`] into `self`), `stream_sink`
  (streaming decode) and `get` (decode a whole value into an owned `Self`,
  `Sized`-only, defaulted via `Default + assign`).
- **`FromStructure`** — reinterpret an already-decoded [`Data::Structure`] into
  a concrete type via `Data::recast::<T>()`.

The `scal-unit-type` structure (`structure { scaler: integer, unit: enum }`) is
a minimal example. The struct **owns** its scalar fields, while the two traits
bridge to/from `Data::Structure`:

```rust
use cosempdu::buffer::{ByteBuffer, Reader};
use cosempdu::data::{Arena, Codec, Data, FromStructure};
use cosempdu::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ScalUnitType {
    scaler: i8,
    unit: u8,
}

impl<'a> FromStructure<'a> for ScalUnitType {
    fn from_structure(fields: &'a [Data<'a>]) -> Result<Self> {
        if fields.len() != 2 {
            return Err(Error::message("expected structure { integer, enum }"));
        }
        let scaler = fields[0].as_integer().ok_or_else(|| Error::message("field 0 must be integer"))?;
        let unit = fields[1].as_enum().ok_or_else(|| Error::message("field 1 must be enum"))?;
        Ok(ScalUnitType { scaler, unit })
    }
}

impl Codec for ScalUnitType {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize> {
        Data::Structure(&[Data::Integer(self.scaler), Data::Enum(self.unit)]).put(buf)
    }

    fn assign(&mut self, data: &Data<'_>) -> Result<()> {
        *self = data.recast::<ScalUnitType>()?;
        Ok(())
    }
    // `get` inherited from the default: Data::get + Default + assign.
}
```

Usage — encode and decode as a `Data::Structure`, or reinterpret an already
decoded `Data` via `recast`:

```rust
let s = ScalUnitType { scaler: 3, unit: 1 };

let mut backing = [0u8; 64];
let mut buf = ByteBuffer::new(&mut backing);
s.put(&mut buf)?; // encodes Data::Structure([Integer(3), Enum(1)])

let mut reader = Reader::new(&backing[..buf.pos()]);
let mut arena_storage = [core::mem::MaybeUninit::uninit(); 16];
let mut arena = Arena::new(&mut arena_storage);
assert_eq!(ScalUnitType::get(&mut reader, &mut arena)?, s);
```

## Related Links

- [X.680](x680.md) — base ASN.1 types
- [AXDR](axdr.md) — A-XDR primitives
- [APDU](apdu.md) — COSEM APDU
- [Buffer](buffer.md) — helper buffers for working with bytes
