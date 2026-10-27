# ACSE — ACSE APDU (ISO/IEC 10035-1)

## Overview

The `acse` module implements ACSE (Association Control Service Element) APDU types according to the ISO/IEC 10035-1 standard and the DLMS/COSEM specification (Green Book 8.3). ACSE messages are used to establish, confirm, and release a logical connection (association) between a DLMS/COSEM client and server.

All ACSE types use BER encoding (X.690) with explicit/implicit context tagging, and are built on primitives from `x680`, `x690`, and `ber`.

- [X.680](x680.md)
- [X690](x690.md)
- [BER](ber.md)
- [AXDR](axdr.md)
- [APDU](apdu.md)

## Module Contents

### APDU Structs

| Struct | ASN.1 Type | Purpose |
|--------|------------|---------|
| `AARQapdu` | `[APPLICATION 0]` SEQUENCE | Association request |
| `AAREapdu` | `[APPLICATION 1]` SEQUENCE | Association response |
| `RLRQapdu` | `[APPLICATION 2]` SEQUENCE | Release request |
| `RLREapdu` | `[APPLICATION 3]` SEQUENCE | Release response |

### AARQ Fields

| Field | Tag | Type |
|-------|-----|------|
| `protocol_version` | `[0]` IMPLICIT BIT STRING | `Option<Vec<u8>>` (usually omitted) |
| `application_context_name` | `[1]` EXPLICIT OID | `Vec<u64>` (arcs) |
| `user_information` | `[30]` EXPLICIT OCTET STRING | `Option<Vec<u8>>` |

`AARQapdu::new(application_context_name)` constructs an empty request with the given OID arcs.

### AARE Fields

| Field | Tag | Type |
|-------|-----|------|
| `protocol_version` | `[0]` IMPLICIT BIT STRING | `Option<Vec<u8>>` |
| `application_context_name` | `[1]` EXPLICIT OID | `Vec<u64>` |
| `result` | `[2]` Association-result | `AssociationResult` |
| `result_source_diagnostic` | `[3]` Associate-source-diagnostic | `AssociateSourceDiagnostic` (CHOICE) |
| `user_information` | `[30]` EXPLICIT OCTET STRING | `Option<Vec<u8>>` |

### Associate-source-diagnostic

`result_source_diagnostic` is an ASN.1 CHOICE of two INTEGER alternatives:

| Enum | Tag | Values |
|------|-----|--------|
| `AcseServiceUser` | `[1]` INTEGER | 0 = null, 1 = no-reason-given, 2 = application-context-name-not-supported, 3 = calling-AP-title-not-recognized, 4 = calling-AP-invocation-identifier-not-recognized, 5 = calling-AE-qualifier-not-recognized, 6 = calling-AE-invocation-identifier-not-recognized, 7 = called-AP-title-not-recognized, 8 = called-AP-invocation-identifier-not-recognized, 9 = called-AE-qualifier-not-recognized, 10 = called-AE-invocation-identifier-not-recognized, 11 = authentication-mechanism-name-not-recognised, 12 = authentication-mechanism-name-required, 13 = authentication-failure, 14 = authentication-required |
| `AcseServiceProvider` | `[2]` INTEGER | 0 = null, 1 = no-reason-given, 2 = no-common-acse-version |

`AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::...)` selects the `[1]`
alternative and `AssociateSourceDiagnostic::ServiceProvider(AcseServiceProvider::...)`
selects the `[2]` alternative. Both are `#[repr(u8)]` enums; unknown values are rejected
during decoding.

### RLRQ / RLRE Fields

| Field | Tag | Type |
|-------|-----|------|
| `reason` | `[0]` IMPLICIT INTEGER | `Option<i64>` |
| `user_information` | `[30]` EXPLICIT OCTET STRING | `Option<Vec<u8>>` |

### Dispatch Type

| Enum | Purpose |
|------|---------|
| `ACSEApdu` | `CHOICE { Aarq, Aare, Rlrq, Rlre }` — detects the APDU by its application tag |

### Methods

Each struct provides `put(buf: &mut ByteBuffer<'_>) -> Result<usize>` (encode) and `get(buf: &mut ByteBuffer<'_>) -> Result<Self>` (decode). `ACSEApdu` additionally provides `put()` and `get()`.

## How It Works

### Association Establishment Flow

```
Client                        Server
  |                             |
  |--- AARQapdu (request) ----->|
  |                             |
  |<--- AAREapdu (response) ----|
  |                             |
  |--- COSEM APDU exchange ---->|
  |                             |
  |--- RLRQapdu (release) ----->|
  |                             |
  |<--- RLREapdu (confirm) -----|
```

### ACSE Message Encoding

All ACSE messages are encoded in BER (X.690). Example AARQ structure:

```
[APPLICATION 0, CONSTRUCTED]  (AARQ tag)
  Length (entire message)
  +-- protocol_version [0] BIT STRING (optional)
  +-- application_context_name [1] EXPLICIT OID
  +-- user_information [30] EXPLICIT OCTET STRING (optional)
        Contains COSEM APDU in A-XDR
```

## Usage

### Encoding an AARQ Request

```rust
use cosempdu::acse::AARQapdu;

let aarq = AARQapdu {
    protocol_version: None,
    application_context_name: vec![2, 16, 756, 5, 8, 1, 1],
    user_information: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
};

let mut backing = [0u8; 4096];
let mut buf = ByteBuffer::new(&mut backing);
aarq.put(&mut buf)?;
let bytes = buf.extract();
```

### Decoding an AARE Response

```rust
use cosempdu::acse::{ACSEApdu, AAREapdu};
use cosempdu::buffer::ByteBuffer;

let mut backing = [0u8; 4096];
backing[..bytes.len()].copy_from_slice(&bytes);
let decoded = ACSEApdu::get(&mut ByteBuffer::new(&mut backing[..bytes.len()]))?;
if let ACSEApdu::Aare(AAREapdu { result, .. }) = decoded {
    println!("result = {result}"); // 0 = accepted
}
```

### Release APDUs

```rust
use cosempdu::acse::{ACSEApdu, RLRQapdu, RLREapdu};
use cosempdu::buffer::ByteBuffer;

let rlrq = ACSEApdu::Rlrq(RLRQapdu { reason: Some(0), user_information: None });
let rlre = ACSEApdu::Rlre(RLREapdu { reason: Some(1), user_information: None });

let mut backing = [0u8; 4096];
let mut buf = ByteBuffer::new(&mut backing);
rlrq.put(&mut buf)?;

buf.set_pos(0)?;
let decoded = ACSEApdu::get(&mut buf)?;
assert_eq!(decoded, rlrq);
```

## Related Links

- [X.680](x680.md) — base ASN.1 types
- [X690](x690.md) — low-level TLV encoding
- [BER](ber.md) — BER codec for `Value` types
- [APDU](apdu.md) — COSEM APDU (nested in UserInformation)
- [Buffer](buffer.md) — helper buffers for working with bytes
