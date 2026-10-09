# BER — ASN.1 Basic Encoding Rules (low-level primitives)

## Overview

The `ber` module contains the low-level, allocation-free BER (X.690) encoding
primitives used by the concrete DLMS/COSEM codecs. It does **not** model the
abstract `Value` types — the ACSE APDUs (`acse.rs`) call these primitives
directly with their own concrete types.

The module provides:
- **ACSE APDU** (`acse.rs`) — all ACSE messages are encoded in BER.

- [X.680](x680.md)
- [X690](x690.md)
- [AXDR](axdr.md)
- [ACSE](acse.md)
- [APDU](apdu.md)

## Module Contents

### TLV Helpers

| Function | Description |
|----------|-------------|
| `put_tlv(buf, tag, content)` | Write a full TLV (tag + length + content) into the buffer |
| `with_content(buf, tag, f)` | Write tag + length prefix, run `f` for the content, then backfill the length |

### INTEGER Content

| Function | Description |
|----------|-------------|
| `put_signed(buf, value)` | Minimal signed two's-complement INTEGER encoding (X.690 §8.3.3) |
| `decode_signed(content)` | Decode big-endian two's-complement content octets into `i64` |

## Usage

### Writing a TLV

```rust
use cosempdu::ber::put_tlv;
use cosempdu::buffer::ByteBuffer;
use cosempdu::x680::{Tag, UniversalTag};

let mut backing = [0u8; 16];
let mut buf = ByteBuffer::new(&mut backing);
put_tlv(&mut buf, &Tag::universal(UniversalTag::Integer), &[0x2A])?; // 02 01 2A
```

## Related Links

- [X.680](x680.md) — tag primitives
- [X690](x690.md) — low-level TLV encoding
- [AXDR](axdr.md) — A-XDR primitives
- [APDU](apdu.md) — COSEM APDU
- [ACSE](acse.md) — ACSE APDU
- [Buffer](buffer.md) — helper buffers for working with bytes

