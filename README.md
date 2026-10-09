# COSEMpdu (Rust)

DLMS/COSEM PDU encoder/decoder for smart metering protocols. Implements ASN.1 types (X.680), A-XDR encoding rules (IEC 61334-6), and BER encoding rules (X.690). This is a Rust port of the `COSEMpdu` Python library.

## Overview

`cosempdu` is a Rust library for working with DLMS/COSEM Protocol Data Units (PDUs) used in smart metering and energy management systems. It implements the COSEM PDU specification from the Green Book (IEC 62056 / EN 13757-1), including:

- **ASN.1 Type System (X.680)** — universal tags, tag classes, the `Value` abstract value types, and constraints
- **A-XDR Encoding (IEC 61334-6:2000)** — size-optimized encoding for the COSEM APDU (Application Protocol Data Unit)
- **BER Encoding (X.690)** — Basic Encoding Rules for the COSEM ACSE (Association Control Service Element)
- **COSEM APDU Types** — the GET service family and the `XDLMSApdu` dispatch type
- **COSEM ACSE Types** — application association and release PDUs

## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
cosempdu = "0.1.0"
```

Requires the Rust 2021 edition.

## Quick Start

### GET-Request PDU (A-XDR)

```rust
use cosempdu::apdu::{CosemAttributeDescriptor, GetRequest, InvokeIdAndPriority};
use cosempdu::buffer::ByteBuffer;

let get = GetRequest::Normal {
    invoke: InvokeIdAndPriority::from_bits(0x1, true, true), // invoke_id=1, confirmed, high priority
    descriptor: CosemAttributeDescriptor {
        class_id: 8,                          // Clock object
        instance_id: [0x00, 0x00, 0x01, 0x00, 0x00, 0xff], // logical name
        attribute_id: 2,                      // attribute #2 (time)
    },
    access_selection: None,
};

let mut backing = [0u8; 4096];
let mut buf = ByteBuffer::new(&mut backing);
get.put(&mut buf)?;                           // encode A-XDR bytes

buf.set_pos(0)?;
let decoded = GetRequest::get(&mut buf)?;     // decode
assert_eq!(decoded, get);
```

### ACSE (BER) Example

```rust
use cosempdu::acse::{AARQapdu, ACSEApdu};
use cosempdu::buffer::ByteBuffer;

let aarq = AARQapdu {
    protocol_version: None,
    application_context_name: vec![2, 16, 756, 5, 8, 1, 1], // LN referencing
    user_information: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
};

let mut backing = [0u8; 4096];
let mut buf = ByteBuffer::new(&mut backing);
aarq.put(&mut buf)?;

buf.set_pos(0)?;
let decoded = ACSEApdu::get(&mut buf)?;
assert_eq!(decoded, ACSEApdu::Aarq(aarq));
```

## Supported Standards

| Standard | Description |
|----------|-------------|
| **IEC 61334-6:2000** | DLMS/COSEM A-XDR encoding rules |
| **X.680** | ASN.1 notation and type definitions |
| **X.690** | BER (Basic Encoding Rules) |
| **IEC 62056 / EN 13757-1** | DLMS/COSEM application layer |

## Modules

| Module | Purpose |
|--------|---------|
| `cosempdu::x680` | ASN.1 type system: universal tags, classes, `Value` types, constraints |
| `cosempdu::x690` | BER Tag and Length encoding primitives, ED helpers |
| `cosempdu::ber` | BER encoding/decoding for `Value` types |
| `cosempdu::axdr` | A-XDR encoding/decoding primitives for DLMS/COSEM |
| `cosempdu::data` | COSEM data types (`Data` choice enum) |
| `cosempdu::apdu` | xDLMS APDU types (GET service family, `XDLMSApdu`) |
| `cosempdu::acse` | ACSE APDU types (AARQ, AARE, RLRQ, RLRE) |
| `cosempdu::buffer` | Byte-level read/write buffers (`ByteBuffer`) |
| `cosempdu::error` | `Error` enum and `Result` alias |

## Documentation

| Document | Module |
|----------|--------|
| [X.680 — ASN.1 Types](doc/x680.md) | `cosempdu::x680` |
| [X.690 — BER Primitives](doc/x690.md) | `cosempdu::x690` |
| [BER Value Codec](doc/ber.md) | `cosempdu::ber` |
| [A-XDR Primitives](doc/axdr.md) | `cosempdu::axdr` |
| [COSEM APDU](doc/apdu.md) | `cosempdu::apdu` |
| [ACSE APDU](doc/acse.md) | `cosempdu::acse` |
| [COSEM Data Types](doc/data.md) | `cosempdu::data` |
| [Byte Buffer](doc/buffer.md) | `cosempdu::buffer` |

## Workspace crates

| Crate | Purpose |
|-------|---------|
| `bytebuffer` | Heap-free byte read/write buffers |
| `cosempdu` | ASN.1/X.680, BER, A-XDR, COSEM APDU/ACSE |
| `server` | Minimal DLMS/COSEM server (per-attribute typed registry) |
| `dlms1` | COSEM Interface Classes and OBIS (DLMS UA 1000-1 Ed. 14) — see [DLMS1](doc/DLMS1.md) |

## Project Links

- **Source code:** [GitHub](https://github.com/youserj/COSEMpdu_project)
- **Issues:** [GitHub Issues](https://github.com/youserj/COSEMpdu_project/issues)

## License

MIT License — see the source repository for details.
