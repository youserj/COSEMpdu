# DLMS1 — COSEM Interface Classes and OBIS (Blue Book, DLMS UA 1000-1 Ed. 14)

> Crate `dlms1`. Builds on `cosempdu` (the COSEM `Data` type and the A-XDR
> codec) and adds the two data-model layers of the DLMS UA 1000-1 Ed. 14
> ("Blue Book"): the OBIS Object Identification System (clause 4) and the COSEM
> interface classes (clause 7). `no_std`-compatible (`core` only).

## Modules

| Module | Purpose |
|--------|---------|
| `dlms1::obis` | [`ObisCode`] `A.B.C.D.E.F`, logical-name form, value-group enums, SN base-name mapping |
| `dlms1::ic` | [`ClassId`], [`InterfaceClass`] trait, common value types, concrete classes |
| `dlms1::common_data_types` | typed values of the DLMS "common data types" (`DoubleLongUnsigned`, `DateTime`, `OctetString`), implementing `cosempdu::Codec` |

## OBIS (clause 4)

```rust
use dlms1::obis::{ObisCode, Medium, Quantity, Processing};

let code: ObisCode = "1.0.1.8.0.255".parse()?;   // +A total
assert_eq!(code.a(), 1);   // Medium::Electricity
assert_eq!(code.c(), 1);   // Quantity::ActivePowerPlus
assert_eq!(code.d(), 8);   // Processing::Integral1
assert_eq!(code.logical_name(), [1, 0, 1, 8, 0, 255]);
assert_eq!(code.base_name(), 0x1018);            // SN base name (clause 4.8)
```

## Interface classes (clause 7)

Each object implements [`InterfaceClass`] and exposes its attributes by number
(`get`/`set`) and its methods by number (`action`). Attribute values are A-XDR
encoded into a caller-provided `ByteBuffer`.

```rust
use dlms1::ic::{ClassId, InterfaceClass, Register, ScalUnit};
use dlms1::obis::ObisCode;
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::Data;

let mut reg = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
reg.value = 42;
reg.scaler_unit = ScalUnit::new(3, 1); // 42e3, unit 1

let mut backing = [0u8; 64];
let n = {
    let mut buf = ByteBuffer::new(&mut backing);
    reg.get(2, &mut buf)?               // attribute 2 = value
};
assert_eq!(&backing[..n], &[0x06, 0x00, 0x00, 0x00, 0x2A]);

reg.set(2, &Data::DoubleLongUnsigned(7))?;   // SET value
reg.action(1, &Data::NullData)?;              // method 1 = reset
assert_eq!(reg.value, 0);
assert_eq!(reg.class_id(), ClassId::Register);
```

### Implemented classes (minimal set)

| Class | id | version | attributes | methods |
|-------|----|---------|------------|---------|
| `DataObject` | 1 | 0 | 1 logical_name, 2 value | — |
| `Register` | 3 | 0 | 1 logical_name, 2 value, 3 scaler_unit | 1 reset |
| `ExtendedRegister` | 4 | 0 | 1 logical_name, 2 value, 3 scaler_unit, 4 status, 5 capture_time | 1 reset |
| `RegisterActivation` | 6 | 0 | 1 logical_name, 2 register_assignment, 3 mask_list, 4 active_mask | 1 add_register, 2 add_mask, 3 delete_mask (deferred) |
| `Clock` | 8 | 0 | 1..8 (time, time_zone, status, begin, end, deviation, clock_base) | 1..6 |
| `AssociationSn` | 12 | 4 | 1..9 (object_list, partners_id, …, security_ref) | 1..4 |
| `AssociationLn` | 15 | 1 | 1..8 (as SN, LN object_list entries) | 1..4 |

`ClassId` enumerates the full Blue Book class-id table; only the seven classes
above have concrete implementations.

## Scope / simplifications

- The association `object_list` stores identifying fields only
  (`class_id`/`version`/`logical_name`, plus `base_name` for SN); the Blue Book
  `access_rights` entry is deferred.
- `XdlmsContextInfo.conformance` is stored as a 32-bit value of the conformance
  bit-string.
- Association methods `add_object`/`remove_object` are reported as unsupported
  (the object list is a borrowed slice); `reply_to_HLS_secret` /
  `change_HLS_secret` are accepted no-ops (HLS secret handling is
  application-specific).
- Clock rounding/shift methods (`adjust_to_quarter`, `adjust_to_measuring_period`,
  `adjust_to_minute`, `shift_time`) are accepted but applied by the platform
  clock.

## Related documents

- [Server](server.md) — the `server` crate (per-attribute registry built on A-XDR).
- [Data](data.md) — COSEM data types.
- [APDU](apdu.md), [ACSE](acse.md) — COSEM PDU / transport.
