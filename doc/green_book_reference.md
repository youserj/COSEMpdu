# DLMS/COSEM Green Book — A-XDR reference (xDLMS APDU)

Выжимка из IEC 62056-5-3 / DLMS UA 1000-2 Ed. 10 (2020), clause 8.3 и 11–12.
Только определения типов, таблицы тегов и байтовые тест-векторы (без прозы,
оглавления и колонтитулов). Для автогенерации кода.

## 1. Кодирование тегов (A-XDR, IEC 61334-6)

- Тег — **один байт** (или два для extended-тегов ≥ 31).
- Универсальные типы `Data` — байты `0x00..0x1E` (см. §6).
- Теги xDLMS-APDU CHOICE — **сырые байты номера тега**: `[1]→0x01`, `[5]→0x05`,
  … `[14]→0x0E`, `[22]→0x16`, `[24]→0x18`, `[192]→0xC0`, `[199]→0xC7`.
- Контекстные теги внутри CHOICE (`[0]`, `[1]`, …) — **сырые байты** `0x00`, `0x01`, …
- Прикладной тег `[APPLICATION 31]` (Conformance) — **BER-style**: `0x5F 0x1F`
  (application class + extended tag 31), затем длина `04`, unused-bits `00`, 3 байта значения.
- `OPTIONAL` / `DEFAULT` — usage-flag байт: `0x00` = отсутствует/дефолт,
  `0xFF` = значение следует. BOOLEAN кодируется `0x00`/`0xFF`.
- `SEQUENCE OF` внутри APDU — `length (count)` + элементы (без тега Array).
- `OCTET STRING` — тег `0x09` + length + байты.
- `Unsigned8/Integer8` — 1 байт; `Unsigned16/Integer16` — 2 байта BE;
  `Unsigned32` — 4 байта BE.

## 2. xDLMS-APDU ::= CHOICE (теги)

```
-- без шифрования (SN referencing)
initiateRequest               [1]  IMPLICIT InitiateRequest
readRequest                   [5]  IMPLICIT ReadRequest
writeRequest                  [6]  IMPLICIT WriteRequest
initiateResponse              [8]  IMPLICIT InitiateResponse
readResponse                  [12] IMPLICIT ReadResponse
writeResponse                 [13] IMPLICIT WriteResponse
confirmedServiceError         [14] ConfirmedServiceError
data-notification             [15] IMPLICIT Data-Notification
data-notification-confirm     [16] IMPLICIT Data-Notification-Confirm
unconfirmedWriteRequest       [22] IMPLICIT UnconfirmedWriteRequest
informationReportRequest      [24] IMPLICIT InformationReportRequest

-- global ciphering (OCTET STRING)
glo-initiateRequest           [33]  IMPLICIT OCTET STRING
glo-readRequest               [37]  IMPLICIT OCTET STRING
glo-writeRequest              [38]  IMPLICIT OCTET STRING
glo-initiateResponse          [40]  IMPLICIT OCTET STRING
glo-readResponse              [44]  IMPLICIT OCTET STRING
glo-writeResponse             [45]  IMPLICIT OCTET STRING
glo-confirmedServiceError     [46]  IMPLICIT OCTET STRING
glo-unconfirmedWriteRequest   [54]  IMPLICIT OCTET STRING
glo-informationReportRequest  [56]  IMPLICIT OCTET STRING

-- dedicated ciphering (OCTET STRING)
ded-initiateRequest           [65]  IMPLICIT OCTET STRING
ded-readRequest               [69]  IMPLICIT OCTET STRING
ded-writeRequest              [70]  IMPLICIT OCTET STRING
ded-initiateResponse          [72]  IMPLICIT OCTET STRING
ded-readResponse              [76]  IMPLICIT OCTET STRING
ded-writeResponse             [77]  IMPLICIT OCTET STRING
ded-confirmedServiceError     [78]  IMPLICIT OCTET STRING
ded-unconfirmedWriteRequest   [86]  IMPLICIT OCTET STRING
ded-informationReportRequest  [88]  IMPLICIT OCTET STRING

-- без шифрования (LN referencing)
get-request                   [192] IMPLICIT Get-Request
set-request                   [193] IMPLICIT Set-Request
event-notification-request    [194] IMPLICIT EventNotificationRequest
action-request                [195] IMPLICIT Action-Request
get-response                  [196] IMPLICIT Get-Response
set-response                  [197] IMPLICIT Set-Response
action-response               [199] IMPLICIT Action-Response

-- global ciphering (LN referencing, OCTET STRING)
glo-get-request               [200] IMPLICIT OCTET STRING
glo-set-request               [201] IMPLICIT OCTET STRING
glo-event-notification-request[202] IMPLICIT OCTET STRING
glo-action-request            [203] IMPLICIT OCTET STRING
glo-get-response              [204] IMPLICIT OCTET STRING
glo-set-response              [205] IMPLICIT OCTET STRING
glo-action-response           [207] IMPLICIT OCTET STRING
```

## 3. SN-сервисы (short name referencing)

```
InitiateRequest ::= SEQUENCE {
    dedicated-key                 OCTET STRING OPTIONAL,
    response-allowed              BOOLEAN DEFAULT TRUE,
    proposed-quality-of-service   IMPLICIT Integer8 OPTIONAL,
    proposed-dlms-version-number  Unsigned8,
    proposed-conformance          Conformance,
    client-max-receive-pdu-size   Unsigned16
}

InitiateResponse ::= SEQUENCE {
    negotiated-quality-of-service  IMPLICIT Integer8 OPTIONAL,
    negotiated-dlms-version-number Unsigned8,
    negotiated-conformance         Conformance,
    server-max-receive-pdu-size    Unsigned16,
    vaa-name                       ObjectName
}

ReadRequest ::= SEQUENCE OF Variable-Access-Specification

ReadResponse ::= SEQUENCE OF CHOICE {
    data                  [0] Data,
    data-access-error     [1] IMPLICIT Data-Access-Result,
    data-block-result     [2] IMPLICIT Data-Block-Result,
    block-number          [3] IMPLICIT Unsigned16
}

WriteRequest ::= SEQUENCE {
    variable-access-specification  SEQUENCE OF Variable-Access-Specification,
    list-of-data                   SEQUENCE OF Data
}

WriteResponse ::= SEQUENCE OF CHOICE {
    success               [0] IMPLICIT NULL,
    data-access-error     [1] IMPLICIT Data-Access-Result,
    block-number          [2] Unsigned16
}

UnconfirmedWriteRequest ::= SEQUENCE {
    variable-access-specification  SEQUENCE OF Variable-Access-Specification,
    list-of-data                   SEQUENCE OF Data
}

InformationReportRequest ::= SEQUENCE {
    current-time                   GeneralizedTime OPTIONAL,
    variable-access-specification  SEQUENCE OF Variable-Access-Specification,
    list-of-data                   SEQUENCE OF Data
}

Data-Notification ::= SEQUENCE {
    long-invoke-id-and-priority    Long-Invoke-Id-And-Priority,
    date-time                      OCTET STRING,
    notification-body              Notification-Body
}

Data-Notification-Confirm ::= SEQUENCE {
    long-invoke-id-and-priority    Long-Invoke-Id-And-Priority,
    date-time                      OCTET STRING
}

Notification-Body ::= SEQUENCE { data-value Data }
```

## 4. Поддерживающие типы (SN)

```
Variable-Access-Specification ::= CHOICE {
    variable-name           [2] IMPLICIT ObjectName,
    -- detailed-access [3] не используется в DLMS/COSEM
    parameterized-access    [4] IMPLICIT Parameterized-Access,
    block-number-access     [5] IMPLICIT Block-Number-Access,
    read-data-block-access  [6] IMPLICIT Read-Data-Block-Access,
    write-data-block-access [7] IMPLICIT Write-Data-Block-Access
}

Parameterized-Access ::= SEQUENCE {
    variable-name           ObjectName,
    selector                Unsigned8,
    parameter               Data
}

Block-Number-Access      ::= SEQUENCE { block-number Unsigned16 }
Read-Data-Block-Access   ::= SEQUENCE { last-block BOOLEAN, block-number Unsigned16, raw-data OCTET STRING }
Write-Data-Block-Access  ::= SEQUENCE { last-block BOOLEAN, block-number Unsigned16 }

Data-Block-Result ::= SEQUENCE { last-block BOOLEAN, block-number Unsigned16, raw-data OCTET STRING }

ObjectName ::= Integer16
-- для named variable objects младшие 3 бита = 000; для vaa-name = 111.

Conformance ::= [APPLICATION 31] IMPLICIT BIT STRING (SIZE(24))
-- кодируется в BER: 5F 1F 04 00 XX XX XX (3 байта значения)

Long-Invoke-Id-And-Priority ::= Unsigned32
```


## 5. Перечисления

```
Data-Access-Result ::= ENUMERATED {
    success(0), hardware-fault(1), temporary-failure(2), read-write-denied(3),
    object-undefined(4), object-class-inconsistent(9), object-unavailable(11),
    type-unmatched(12), scope-of-access-violated(13), data-block-unavailable(14),
    long-get-aborted(15), no-long-get-in-progress(16), long-set-aborted(17),
    no-long-set-in-progress(18), data-block-number-invalid(19), other-reason(250)
}

ConfirmedServiceError ::= CHOICE {
    initiateError [1] ServiceError, getStatus [2] ServiceError,
    getNameList [3] ServiceError, getVariableAttribute [4] ServiceError,
    read [5] ServiceError, write [6] ServiceError,
    getDataSetAttribute [7] ServiceError, getTIAttribute [8] ServiceError,
    changeScope [9] ServiceError, start [10] ServiceError, stop [11] ServiceError,
    resume [12] ServiceError, makeUsable [13] ServiceError,
    initiateLoad [14] ServiceError, loadSegment [15] ServiceError,
    terminateLoad [16] ServiceError, initiateUpLoad [17] ServiceError,
    upLoadSegment [18] ServiceError, terminateUpLoad [19] ServiceError
}

ServiceError ::= CHOICE {
    application-reference [0] IMPLICIT ENUMERATED {
        other(0), time-elapsed(1), application-unreachable(2),
        application-reference-invalid(3), application-context-unsupported(4),
        provider-communication-error(5), deciphering-error(6) },
    hardware-resource [1] IMPLICIT ENUMERATED {
        other(0), memory-unavailable(1), processor-resource-unavailable(2),
        mass-storage-unavailable(3), other-resource-unavailable(4) },
    vde-state-error [2] IMPLICIT ENUMERATED {
        other(0), no-dlms-context(1), loading-data-set(2),
        status-nochange(3), status-inoperable(4) },
    service [3] IMPLICIT ENUMERATED {
        other(0), pdu-size(1), service-unsupported(2) },
    definition [4] IMPLICIT ENUMERATED {
        other(0), object-undefined(1), object-class-inconsistent(2),
        object-attribute-inconsistent(3) },
    access [5] IMPLICIT ENUMERATED {
        other(0), scope-of-access-violated(1), object-access-violated(2),
        hardware-fault(3), object-unavailable(4) },
    initiate [6] IMPLICIT ENUMERATED {
        other(0), dlms-version-too-low(1), incompatible-conformance(2),
        pdu-size-too-short(3), refused-by-the-VDE-Handler(4) },
    load-data-set [7] IMPLICIT ENUMERATED {
        other(0), primitive-out-of-sequence(1), not-loadable(2),
        dataset-size-too-large(3), not-awaited-segment(4),
        interpretation-failure(5), storage-failure(6), data-set-not-ready(7) },
    task [9] IMPLICIT ENUMERATED {
        other(0), no-remote-control(1), ti-stopped(2), ti-running(3), ti-unusable(4) }
}
```

## 6. Data ::= CHOICE (универсальные теги A-XDR)

```
null-data            [0]  NULL            double-long       [5]  Integer32
array                [1]  SEQUENCE OF Data double-long-uns  [6]  Unsigned32
structure            [2]  SEQUENCE OF Data octet-string     [9]  OCTET STRING
boolean              [3]  BOOLEAN         visible-string    [10] VisibleString
bit-string           [4]  BIT STRING      utf8-string       [12] UTF8String
                                          bcd               [13] Integer8
integer              [15] Integer8        long              [16] Integer16
unsigned             [17] Unsigned8       long-unsigned     [18] Unsigned16
compact-array        [19] SEQUENCE { contents-description [0] TypeDescription,
                                     array-contents [1] IMPLICIT OCTET STRING }
long64               [20] Integer64       long64-unsigned   [21] Unsigned64
enum                 [22] ENUMERATED      float32           [23]
float64              [24]                 date-time         [25] OCTET STRING(SIZE(12))
date                 [26] OCTET STRING(SIZE(5))
time                 [27] OCTET STRING(SIZE(4))
dont-care            [255]
```

## 7. LN-сервисы (кратко)

```
Get-Request ::= CHOICE {
    get-request-normal      [1] IMPLICIT SEQUENCE { invoke-id-and-priority,
                              cosem-attribute-descriptor, access-selection OPTIONAL },
    get-request-next        [2] IMPLICIT SEQUENCE { invoke-id-and-priority, block-number Unsigned32 },
    get-request-with-list   [3] IMPLICIT SEQUENCE { invoke-id-and-priority,
                              SEQUENCE OF (Cosem-Attribute-Descriptor, access-selection OPTIONAL) }
}

Get-Response ::= CHOICE {
    get-response-normal      [1] Get-Data-Result,
    get-response-with-block  [2] DataBlock-G,
    get-response-with-list   [3] SEQUENCE OF Get-Data-Result
}

Get-Data-Result ::= CHOICE { data [0] Data, data-access-result [1] IMPLICIT Data-Access-Result }
DataBlock-G ::= SEQUENCE { last-block BOOLEAN, block-number Unsigned32,
                           result CHOICE { raw-data [0] OCTET STRING, data-access-result [1] } }
DataBlock-SA ::= SEQUENCE { last-block BOOLEAN, block-number Unsigned32, raw-data OCTET STRING }

Set-Request / Set-Response / Action-Request / Action-Response / EventNotificationRequest —
см. `cosempdu/src/apdu.rs` (уже реализованы).
```


## 8. Conformance block (24 бита)

`Conformance ::= [APPLICATION 31] IMPLICIT BIT STRING (SIZE(24))`. Бит 0 — MSB
первого октета.

| Бит | Имя | LN | SN |
|---|---|---|---|
| 0 | reserved-zero | | |
| 1 | reserved-one | | |
| 2 | reserved-two | | |
| 3 | read | | ✓ |
| 4 | write | | ✓ |
| 5 | unconfirmed-write | | ✓ |
| 6 | reserved-six | | |
| 7 | reserved-seven | | |
| 8 | attribute0-supported-with-set | ✓ | |
| 9 | priority-mgmt-supported | ✓ | |
| 10 | attribute0-supported-with-get | ✓ | |
| 11 | block-transfer-with-get-or-read | ✓ | |
| 12 | block-transfer-with-set-or-write | ✓ | |
| 13 | block-transfer-with-action | ✓ | |
| 14 | multiple-references | ✓ | |
| 15 | information-report | ✓ | |
| 16 | data-notification | ✓ | |
| 17 | access | ✓ | |
| 18 | parameterized-access | ✓ | |
| 19 | get | ✓ | |
| 20 | set | ✓ | |
| 21 | selective-access | ✓ | |
| 22 | event-notification | ✓ | |
| 23 | action | ✓ | |

## 9. Тест-векторы (точные байты из Green Book)

### 9.1 InitiateRequest (SN referencing, Table 116)

`01 00 00 00 06 5F 1F 04 00 1C 03 20 04 B0`

| Байты | Поле |
|---|---|
| `01` | тег xDLMS-APDU CHOICE (InitiateRequest [1]) |
| `00` | dedicated-key usage-flag (отсутствует) |
| `00` | response-allowed usage-flag (дефолт TRUE) |
| `00` | proposed-quality-of-service usage-flag (отсутствует) |
| `06` | proposed-dlms-version-number = 6 |
| `5F 1F 04 00 1C 03 20` | proposed-conformance (Conformance) |
| `04 B0` | client-max-receive-pdu-size = 1200 |

### 9.2 InitiateResponse (SN referencing, Table 117)

`08 00 06 5F 1F 04 00 1C 03 20 01 F4 FA 00`

| Байты | Поле |
|---|---|
| `08` | тег InitiateResponse [8] |
| `00` | negotiated-quality-of-service usage-flag (отсутствует) |
| `06` | negotiated-dlms-version-number = 6 |
| `5F 1F 04 00 1C 03 20` | negotiated-conformance |
| `01 F4` | server-max-receive-pdu-size = 500 |
| `FA 00` | vaa-name (ObjectName Integer16) = 0xFA00 |

### 9.3 ConfirmedServiceError (failure case 2)

`0E 01 06 01`

| Байты | Поле |
|---|---|
| `0E` | тег ConfirmedServiceError [14] |
| `01` | ConfirmedServiceError CHOICE: initiateError [1] |
| `06` | ServiceError CHOICE: initiate [6] |
| `01` | ENUMERATED: dlms-version-too-low (1) |

### 9.4 InitiateRequest с Conformance (LN referencing, Table 116)

`01 00 00 00 06 5F 1F 04 00 00 7E 1F 04 B0` (proposed-conformance = `00 7E 1F`)

