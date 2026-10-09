# AXDR — A-XDR Encoding (IEC 61334-6)

## Overview

The `axdr` module implements A-XDR (Adapted eXtended Data Representation) encoding/decoding primitives according to the IEC 61334-6 standard. A-XDR is a simplified ASN.1 type encoding format used in DLMS/COSEM protocols for data transfer between meters and data collection systems.

Unlike BER, A-XDR:
- **Does not encode tags** for most types (only for CHOICE and explicit tags)
- **Does not encode length** for simple fixed-size types
- Uses **compact representation** to save bandwidth

A-XDR omits the BER tag/length overhead for types whose shape is already known from the schema; only variable-length aggregates carry a length prefix (encoded as a variable-length integer).

The module is used by:
- **COSEM APDU** (`apdu.rs`) — all APDU messages are encoded in A-XDR
- **Data** (`data.rs`) — COSEM Data types

- [X.680](x680.md)
- [X690](x690.md)
- [BER](ber.md)
- [Data](data.md)
- [APDU](apdu.md)

## Module Contents

### Length Primitives (variable-length integer)

| Function | Description |
|----------|-------------|
| `get_length(buf)` | Decode a variable-length integer (IEC 61334-6 §6.1.2) |
| `put_length(buf, value)` | Encode a variable-length integer (short/long form) |

Short form (0-127) occupies a single octet; long form uses a length octet (bit 8 set, bits 7-1 = number of value octets) followed by big-endian bytes.

### OCTET STRING / String Primitives

| Function | Description |
|----------|-------------|
| `get_octet_string(buf)` | Decode a length-prefixed OCTET STRING (IEC 61334-6 §6.3) |
| `put_octet_string(buf, value)` | Encode a length-prefixed OCTET STRING |
| `get_string(buf)` | Decode a length-prefixed visible/UTF-8 string |
| `put_string(buf, value)` | Encode a length-prefixed string (ASCII/UTF-8 bytes) |

### BIT STRING Primitives

| Function | Description |
|----------|-------------|
| `get_bit_string(buf)` | Decode a variable-length BIT STRING; returns bits (0/1) MSB-first |
| `put_bit_string(buf, bits)` | Encode a variable-length BIT STRING from MSB-first bits |

## Usage

### Variable-Length Integer

```rust
use cosempdu::axdr::{get_length, put_length};
use cosempdu::buffer::ByteBuffer;

let mut backing = [0u8; 8];
let mut buf = ByteBuffer::new(&mut backing);
put_length(&mut buf, 127)?;   // short form: 0x7f
put_length(&mut buf, 300)?;   // long form: 0x82 0x01 0x2c

buf.set_pos(0)?;
assert_eq!(get_length(&mut buf)?, 127);
assert_eq!(get_length(&mut buf)?, 300);
```

### OCTET STRING

```rust
use cosempdu::axdr::{get_octet_string, put_octet_string};
use cosempdu::buffer::ByteBuffer;

let mut backing = [0u8; 16];
let mut buf = ByteBuffer::new(&mut backing);
put_octet_string(&mut buf, &[1, 2, 3])?;

buf.set_pos(0)?;
assert_eq!(get_octet_string(&mut buf)?, vec![1, 2, 3]);
```

### BIT STRING

```rust
use cosempdu::axdr::{get_bit_string, put_bit_string};
use cosempdu::buffer::ByteBuffer;

let bits = vec![1, 0, 1, 0, 1, 0, 1, 0, 1, 0];
let mut backing = [0u8; 16];
let mut buf = ByteBuffer::new(&mut backing);
put_bit_string(&mut buf, &bits)?;

buf.set_pos(0)?;
assert_eq!(get_bit_string(&mut buf)?, bits);
```

## Related Links

- [X.680](x680.md) — base ASN.1 types
- [BER](ber.md) — BER codec for `Value` types
- [X690](x690.md) — low-level TLV encoding
- [Data](data.md) — COSEM Data types
- [APDU](apdu.md) — COSEM APDU
- [Buffer](buffer.md) — helper buffers for working with bytes
