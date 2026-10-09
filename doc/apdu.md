# APDU — COSEM APDU (IEC 62056-5-3)

## Overview

The `apdu` module implements the xDLMS APDU (Application Protocol Data Unit) types according to the IEC 62056-5-3 standard and the DLMS/COSEM Green Book 8.3 specification. It mirrors the confirmed GET/SET/ACTION request-response services; this port implements the LN-referencing services (GET/SET/ACTION/EventNotification) plus the `XDLMSApdu` dispatch type.

APDU messages are embedded in ACSE `UserInformation` and transmitted over a BER session. The module uses A-XDR encoding (`axdr.rs`) and COSEM Data types (`data.rs`).

- [X.680](x680.md)
- [AXDR](axdr.md)
- [Data](data.md)
- [ACSE](acse.md)

## Module Contents

### Base Types

| Type | Description |
|------|-------------|
| `InvokeIdAndPriority(pub u8)` | Unsigned8 bit field: invoke-id + service class + priority |
| `CosemAttributeDescriptor` | SEQUENCE { class-id, instance-id, attribute-id } |
| `SelectiveAccessDescriptor` | SEQUENCE { access-selector, access-parameters } |

`CosemAttributeDescriptor` fields: `class_id: u16`, `instance_id: [u8; 6]` (OBIS code), `attribute_id: i8`.
`SelectiveAccessDescriptor` fields: `access_selector: u8`, ccess_parameters: Data<'a>.

### InvokeIdAndPriority

| Method | Description |
|--------|-------------|
| `from_bits(invoke_id, confirmed, high_priority)` | Build from individual fields |
| `invoke_id()` | Extract the 4-bit invoke id |
| `is_confirmed()` | Service class bit (1 = confirmed) |
| `is_high_priority()` | Priority bit (1 = high) |

### GET Services

| Type | Purpose |
|------|---------|
| `GetRequest` | `[192] IMPLICIT CHOICE` — Normal / Next / WithList |
| `GetResponse` | `[196] IMPLICIT CHOICE` — Normal / WithDatablock / WithList |
| `GetDataResult` | `CHOICE { data [0], data-access-error [1] }` |
| `DataBlockG` | `SEQUENCE { last-block, block-number, result }` |
| `DataBlockGResult` | `CHOICE { raw-data [0], data-access-result [1] }` |

### SET Services

| Type | Purpose |
|------|---------|
| `SetRequest` | `[193] IMPLICIT CHOICE` — Normal / WithFirstDatablock / WithDatablock / WithList / WithListAndFirstDatablock |
| `SetResponse` | `[197] IMPLICIT CHOICE` — Normal / Datablock / LastDatablock / LastDatablockWithList / WithList |

### ACTION Services

| Type | Purpose |
|------|---------|
| `ActionRequest` | `[195] IMPLICIT CHOICE` — Normal / NextPblock / WithList / WithFirstPblock / WithListAndFirstPblock / WithPblock |
| `ActionResponse` | `[199] IMPLICIT CHOICE` — Normal / WithPblock / WithList / NextPblock |

### Event Notification

| Type | Purpose |
|------|---------|
| `EventNotificationRequest` | `[194] IMPLICIT SEQUENCE { time OPTIONAL, cosem-attribute-descriptor, attribute-value }` |

### Supporting Types

| Type | Purpose |
|------|---------|
| `CosemMethodDescriptor` | SEQUENCE { class-id, instance-id, method-id } |
| `DataBlockSA` | SEQUENCE { last-block, block-number, raw-data } |
| `ActionResponseWithOptionalData` | SEQUENCE { result, return-parameters OPTIONAL } |

### Dispatch Type

| Type | Purpose |
|------|---------|
| `XDLMSApdu` | `CHOICE { GetRequest, SetRequest, EventNotificationRequest, ActionRequest, GetResponse, SetResponse, ActionResponse }` — detects the APDU by its leading tag byte |

## Usage

> **Decoding** (`get`) now takes an immutable `Reader` plus an `Arena` (zero-copy): `X::get(&mut reader, &mut arena)`. Encoding (`put`) still writes into a mutable `ByteBuffer`.

### Building a GET Request

```rust
use cosempdu::apdu::{CosemAttributeDescriptor, GetRequest, InvokeIdAndPriority};
use cosempdu::buffer::ByteBuffer;

let request = GetRequest::Normal {
    invoke: InvokeIdAndPriority::from_bits(1, true, false),
    descriptor: CosemAttributeDescriptor {
        class_id: 7,                             // Register
        instance_id: [0x01, 0x00, 0x01, 0x08, 0x00, 0xFF],
        attribute_id: 2,                         // value
    },
    access_selection: None,
};

let mut backing = [0u8; 4096];
let mut buf = ByteBuffer::new(&mut backing);
request.put(&mut buf)?;
let bytes = buf.extract();
```

### Handling a GET Response

```rust
use cosempdu::apdu::{GetDataResult, GetResponse};
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::Data;

let mut backing = [0u8; 4096];
backing[..received_bytes.len()].copy_from_slice(&received_bytes);
let mut buf = ByteBuffer::new(&mut backing[..received_bytes.len()]);
let response = GetResponse::get(&mut buf)?;

if let GetResponse::Normal { result: GetDataResult::Data(Data::Long64(v)), .. } = response {
    println!("value = {}", v.0);
}
```

### Decoding a GET Request with a List

```rust
use cosempdu::apdu::GetRequest;
use cosempdu::buffer::ByteBuffer;

let mut backing = [0u8; 4096];
backing[..bytes.len()].copy_from_slice(&bytes);
let mut buf = ByteBuffer::new(&mut backing[..bytes.len()]);

if let GetRequest::WithList { invoke, descriptors } = GetRequest::get(&mut buf)? {
    println!("{} descriptors", descriptors.len());
}
```

### Dispatching an XDLMS APDU

```rust
use cosempdu::apdu::XDLMSApdu;
use cosempdu::buffer::ByteBuffer;

let mut backing = [0u8; 4096];
backing[..bytes.len()].copy_from_slice(&bytes);
let mut buf = ByteBuffer::new(&mut backing[..bytes.len()]);

let apdu = XDLMSApdu::get(&mut buf)?;
match apdu {
    XDLMSApdu::GetRequest(_) => println!("GET request"),
    XDLMSApdu::GetResponse(_) => println!("GET response"),
}
```

## APDU Exchange Diagram

```
Client                                        Server
  |                                             |
  |--- GET-Request [192] ---------------------->|
  |   + CosemAttributeDescriptor                |
  |     + class_id: 7 (Register)                |
  |     + instance_id: OBIS                     |
  |     + attribute_id: 2 (value)               |
  |                                             |
  |<--- GET-Response [196] ---------------------|
  |   + result: Data(DoubleLongUnsigned(230000))|
```

## Related Links

- [X.680](x680.md) — base ASN.1 types
- [AXDR](axdr.md) — A-XDR primitives
- [Data](data.md) — COSEM Data types
- [ACSE](acse.md) — ACSE APDU (transport layer)
- [BER](ber.md) — BER codec for `Value` types
- [Buffer](buffer.md) — helper buffers for working with bytes
