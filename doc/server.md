# План реализации сервера (DLMS/COSEM Server)

> Рабочий документ. Здесь фиксируются требования и проектные решения к
> серверной части, построенной поверх модулей `cosempdu` (ACSE + xDLMS APDU).
> Требования дополняются по мере появления.

## Обзор

Сервер принимает входящие APDU (GET/SET/ACTION), хранит COSEM-объекты и их
атрибуты, формирует ответные APDU. Транспорт — BER-сессия ACSE, вложенный
полезный груз — xDLMS APDU (A-XDR).

Подход к хранению — **типизированные значения** + **права доступа**. Сервер
хранит ROM-таблицу дескрипторов [`AttrDesc`] (ключ + права доступа [`Access`] +
способ хранения [`AttrKind`]). Конкретные значения (реализующие
`cosempdu::Codec`) кодируются (`put`) и декодируются (`assign`/`stream_sink`)
сами; мутабельные значения лежат в RAM-слотах.

## Модель данных (реализовано в `server/src/lib.rs` и `server/src/session.rs`)

```rust
/// Настройки/состояние ассоциации — одновременно контекст доступа запроса.
///
/// `is_ciphered()` выводится из `app_context`; `is_digitally_signed()` — заглушка
/// (`false`, TODO: из `security_suite` атрибута SecuritySetup после client_SAP).
pub struct Settings {
    pub conformance: Conformance,     // согласованный (AARQ/AARE)
    pub assoc_idx: u8,                // индекс Association LN в каталоге (AttrKey.object)
    pub client_sap: u8,               // 0x10 public / 0x20 reader / 0x30 configurator
    pub authenticated: bool,          // аутентификация выбрана (sender-acse-requirements, бит 0)
    pub app_context: ApplicationContextName, // шифрование → is_ciphered()
    pub system_title_c: Option<SystemTitle>, // calling-AP-title клиента (из AARQ)
    pub dedicated_key: DedicatedKey,  // AES-128/256 (features aes128/aes256)
    pub tx_max: u16,                  // min(MAX_APDU, client_max_receive_pdu_size)
    pub state: AssociationState,
}

/// Права доступа к атрибуту — по уровням (client_SAP).
pub struct Access {
    pub public: AttributeAccessMode,       // 0x10
    pub reader: AttributeAccessMode,       // 0x20
    pub configurator: AttributeAccessMode, // 0x30
}

/// Объектно-безопасный кодек типизированного значения (в `cosempdu`).
pub trait Codec { /* put / assign / stream_sink / get */ }

pub struct AttributeKey {            // ключ = OBIS + attribute_id (провод/публичный API)
    pub obis: ObisCode,
    pub attribute_id: i8,            // ASN.1 Integer8 — как на проводе
}

pub struct AttrKey {                 // ключ атрибута в ROM-реестре (без OBIS)
    pub object: u16,                 // индекс объекта в отсортированном каталоге
    pub attribute_id: i8,            // тот же Integer8, без конверсий на границе
}

pub struct AttrSpec {                // спецификация для merge_attrs (compile-time вход)
    pub key: AttributeKey,           // OBIS + номер атрибута
    pub access: Access,
    pub kind: AttrKind,
}

/// Как хранится/меняется значение (вход/транзиентный вид; compile-time).
pub enum AttrKind {
    Static(&'static dyn Codec),  // read-only: кодек (вход для merge_attrs)
    Dynamic(u16),                 // меняет только сервер: индекс RAM-слота
    Persistent(u16),              // SET извне + NVM: индекс RAM-слота
}

/// Как хранится значение в ROM-дескрипторе (все варианты — слот `u16`).
pub enum RomKind {
    Static(u16),      // слот в ROM-массиве кодеков (merge_codecs)
    Dynamic(u16),     // слот в RAM-массиве
    Persistent(u16),  // слот в RAM-массиве
}

/// ROM-дескриптор атрибута (ключ + права + способ хранения).
pub struct AttrDesc {
    pub key: AttrKey,
    pub access: Access,
    pub kind: RomKind,
}

pub struct Server<const N: usize = 3> {
    // каталог COSEM-объектов + ROM-таблица AttrDesc + ROM-массив кодеков +
    // RAM-слоты мутабельных указателей + conformance + пулы-счётчики (лимит N)
}

impl<const N: usize> Server<N> {
    pub fn with_capacity(
        objects: &'static [&'static dyn InterfaceClass],
        attrs: &'static [AttrDesc],                               // ROM
        mutable: &'static mut [Option<&'static mut dyn Codec>],   // RAM-слоты
        conformance: Conformance,
    ) -> Self;
    pub fn handle_get(&self, invoke, descriptor, ctx: &Settings, buf) -> Result<usize, Error>; // GET → Get-Response в buf (проверка can_read)
    pub fn stream_set(&mut self, class_id, key, ctx: &Settings) -> Result<StreamingSet, DataAccessResult>; // stream → Persistent (проверка can_write)
    pub fn update(&mut self, key, data) -> Result<(), Error>;                               // assign → Dynamic (внутреннее)
}
```

- Реестр — это ROM `static`-таблица [`AttrDesc`] (ключ [`AttrKey`] = индекс
  объекта + номер атрибута): OBIS резолвится в индекс объекта, а Static-кодеки
  выносятся в отдельный ROM-массив (`merge_codecs`) — в [`AttrDesc`] остаётся
  слот `u16` ([`RomKind`]), поэтому fat-ptr не тиражируется на Dynamic/Persistent
  ([`AttrDesc`] ≈ 12 Б на 64-bit). Сортировка по ключу — compile-time (`merge_attrs`),
  поиск — `binary_search_by_key` (O(log n)). OBIS в ключе не дублируется (уже в объекте).
- Каталог объектов также отсортирован по OBIS на этапе компиляции
  ([`merge_objects`] + макрос `objects!`): `find_object` использует
  `binary_search_by_key` (O(log n)). OBIS-пары — только compile-time вход для
  сортировки, в рантайм-каталоге остаются лишь отсортированные указатели
  (`&[&dyn InterfaceClass]`, без дублирования OBIS).
- Нет байтового пула: тип сам кодирует/декодирует/валидирует.
- Дескрипторы [`AttrDesc`] — `Copy` и лежат в ROM (`static`-массив); мутабельные
  указатели — в RAM-слотах (`static mut MUT`). Для embedded объекты и дескрипторы —
  `static`, слоты заполняются в `main` (`&mut` на static-объекты).
- Куча не используется (no-heap, готово к `no_std`).

## Уровни доступа (client_SAP)

Уровни соответствуют стандартным DLMS client_SAP (см. `dlms1::ic::association_ln::client_sap`):

- `0x10` — Public client;
- `0x20` — Reader;
- `0x30` — Configurator;
- `0x40` — HLS client (пока не задействован, планируется отдельным `feature`).

`Access { public, reader, configurator }` хранит режим доступа (`AttributeAccessMode`,
0..6, из Association LN) для каждого уровня. `AttributeAccessMode::{can_read, can_write}`
и `MethodAccessMode::can_call` учитывают флаг `authenticated` из `Settings`.

`put(key, ctx, buf)` проверяет `access.can_read(ctx)`, `stream_set(key, ctx)` —
`access.can_write(ctx)`; нарушение → `DataAccessResult::ScopeOfAccessViolated`.

Пример: атрибут читают Public и Configurator (но не Reader), пишет только Configurator:

```rust
// права задаются в ROM-дескрипторе AttrDesc { access: acc, kind: AttrKind::Persistent(slot) }
let acc = Access {
    public: AttributeAccessMode::ReadOnly,
    reader: AttributeAccessMode::NoAccess,
    configurator: AttributeAccessMode::ReadAndWrite,
};
// put(key, &Settings::public(), buf)          -> Ok
// put(key, &Settings::reader(), buf)          -> Err(ScopeOfAccessViolated)
// stream_set(key, &Settings::configurator())  -> Ok
// stream_set(key, &Settings::public())        -> Err(ScopeOfAccessViolated)
```

## Поток данных

- **Клиент → сервер (SET):** клиент подаёт A-XDR байты в `stream_set` → `StreamDecoder`
  декодирует прямо в атрибут через `StreamSink` (проверка `write`). Буферный путь
  (`Data` целиком) не используется.
- **Сервер → клиент (PUT):** `put(key, level, buf)` → проверка `read` → `put` в `ByteBuffer`.
- `Dynamic` сервер меняет сам (`update` из готового `Data`, без уровня), отдаётся через `put`.

## Транспорт и сессии

Соединение обслуживает **`Session`** — значение с `settings: Settings`
(состояние ассоциации), буферами `rx`/`tx` и `transport_ref` (плюс приватные
`media`/`invoke_id`). **`Session` принадлежит вызывающему** (задаче соединения
или `serve`), а не `Server`. Поэтому I/O канала читает/пишет в
`session.rx`/`session.tx` и **не требует `&mut Server`** — мьютекс нужен только
на короткую фазу разбора/кодирования; части сессии раздаются через
`Session::parts()` → `(&mut Settings, &mut TransportRef, &rx, &mut tx)`.

`Server` хранит только каталог объектов, реестр атрибутов, `proposed_conformance`
и пулы-счётчики транспортных слотов (лимит `N`).

```rust
impl<const N: usize> Server<N> {
    // Жизненный цикл соединения
    pub fn on_connect(&mut self, media: Media) -> Result<Session, Error>;   // занять слот → Session
    pub fn on_disconnect(&mut self, media: Media);                          // освободить слот

    // DLMS-слой (без сетевого I/O — читает rx, пишет tx; части сессии через Session::parts())
    pub fn process_request(&mut self, settings: &mut Settings, transport_ref: &mut TransportRef,
                           rx: &ArrayBuffer<RX_BUF>, tx: &mut ArrayBuffer<RX_BUF>,
                           received: Wrapper) -> Result<bool, Error>; // AARQ/Get/Set/RLRQ; false = ответ подавлен

    // Get-Request (Normal) → Get-Response; принимает декодированные owned-поля
    pub fn handle_get(&self, invoke: InvokeIdAndPriority, descriptor: CosemAttributeDescriptor, ctx: &Settings, buf: &mut ByteBuffer<'_>) -> Result<usize, Error>;

    // Весь цикл соединения (AARQ/AARE, GET/SET, RLRQ — через process_request)
    pub async fn serve<C: Channel<Frame = Wrapper>>(&mut self, media: Media, channel: C) -> Result<(), Error>;
}
```

Поток на одно соединение:

```
on_connect(media) -> Session
      │
      ▼  (цикл обслуживания: read → process → write)
received = channel.read(session.rx_mut())       // WPDU-заголовок + APDU
session.set_rx_len(received.apdu_len())
send = process_request(settings, transport_ref, rx, tx, received)  // AARQ/Get/Set/RLRQ
if send { channel.write(session.tx()) }
      │  … до RLRQ/таймаута/закрытия/ошибки
      ▼
on_disconnect(media)
```

- Валидация Wrapper-заголовка (`validate_wrapper`) выполняется внутри
  `process_request`; после успешной ассоциации
  `session.settings.state = Associated`.
- `handle_get` декодирует `Get-Request` в owned-`Copy` поля (`InvokeIdAndPriority`,
  `CosemAttributeDescriptor`) — ссылка на буфер приёма гаснет сразу; обработка
  идёт по частям сессии (`session.parts()`), мьютекс `Server` держится только на
  разбор/кодирование.
- `serve` — обёртка `on_connect` → цикл (приватный `handle_request`, включая AARQ)
  → `on_disconnect` для однопоточного embedded-сценария. `tcp-pc-server` вместо неё
  делает read/process/write вручную, не удерживая мьютекс на I/O.

## HLS-аутентификация (4-pass handshake)

Для всех механизмов HLS (GMAC, SHA-256, ECDSA и др.) используется
**четырёхэтапный** процесс. AARQ/AARE задействованы только на первых двух
этапах, pass 3/4 идут через ACTION-метод `reply_to_HLS_authentication`
(Association LN, class_id 15, OBIS 0.0.40.0.0.255, method_id 1). Второй AARQ
**не** отправляется.

- **Pass 1 (AARQ, клиент → сервер):** CtoS (client challenge) в
  `calling-authentication-value`; system title клиента в `calling-AP-title`
  (если нужен); сертификат/открытый ключ клиента в `calling-AE-qualifier`
  (для ECDSA).
- **Pass 2 (AARE, сервер → клиент):** StoC (server challenge) в
  `responding-authentication-value`; system title сервера в `responding-AP-title`;
  результат `accepted` + HLS success (0x0E = `acse-service-user:
  authentication-required`, TODO подтвердить).
- **Pass 3 (ACTION-request):** клиент шлёт f(StoC) методом
  `reply_to_HLS_authentication` (method_id 1).
- **Pass 4 (ACTION-response):** сервер возвращает f(CtoS) в ответе того же метода.

Pass 3/4 — follow-up: нужны `ActionRequest`/`ActionResponse` APDU в `cosempdu`
(пока не реализованы).

### `CallingAeQualifier` (ECDSA)

```rust
#[cfg(any(feature = "ecdsa_p256", feature = "ecdsa_p384"))]
pub enum CallingAeQualifier {
    None,
    #[cfg(feature = "ecdsa_p256")] P256([u8; 64]), // x || y
    #[cfg(feature = "ecdsa_p384")] P384([u8; 96]), // x || y
}
```

Как и `DedicatedKey`, хранится значением (`None` = отсутствует), но **не** в
постоянной RAM сессии: живёт в shared-скретче `HlsHandshake` только на время
handshake.

### Скретч `HlsHandshake`

```rust
struct HlsHandshake {
    busy: bool,                    // true — идёт проверка → rejected-transient
    ctos: [u8; 16],                // client challenge (pass 1)
    stoc: [u8; 16],                // server challenge (pass 2; TODO: RNG)
    qualifier: CallingAeQualifier, // сертификат клиента
}
```

Один на процесс (`static mut` + `hls_handshake()`): handshake сериализуется;
занят → `rejected-transient`. Освобождается после pass 3 (TODO: таймаут, если
клиент не пришлёт ACTION-ответ).

### Фичи ACSE-полей (cosempdu)

Поля `AARQapdu`, не нужные без соответствующих фич, выносятся за `#[cfg]`
(экономия ROM/RAM в `no_std`). Парсинг содержимого поля обязателен всегда — за
фичу выносится только поле структуры и его присваивание:

```rust
pub struct AARQapdu<'a> {
    ...
    #[cfg(any(feature = "ecdsa_p256", feature = "ecdsa_p384"))]
    pub calling_ae_qualifier: Option<&'a [u8]>,   // сертификат (ECDSA)
    #[cfg(feature = "association_ln_v2")]
    pub calling_ae_invocation_id: Option<i64>,    // HLS (Association LN v2+)
    ...
}
```

Фичи: `cosempdu` — `ecdsa_p256`, `ecdsa_p384`, `association_ln_v2`;
`server` пробрасывает их и добавляет свои.

## Валидация и восстановление

- `assign` — декодирует `Data` в конкретный тип и проверяет его (тег для базы,
  `recast`/`FromStructure` для структур). Не тот тип → `Error::TypeMismatch`.
  Используется для внутреннего `update` (`Dynamic`); внешний SET валидируется
  поточно в `StreamSink` (`stream_set`).
- Заводской дефолт для восстановления при потере/порче NVM — из `AttributeInfo.default`.

## Энергонезависимая память (NVM)

`Persistent`-атрибуты переживают перезагрузку. NVM подключается через трейт:

```rust
pub trait Nvm {
    fn load(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), Error>;
    fn save(&mut self, offset: usize, buf: &[u8]) -> Result<(), Error>;
    fn commit(&mut self) -> Result<(), Error>;
}
```

- Старт: загрузить `Persistent` из NVM → `assign` (декодировать + проверить).
- `stream_set` на `Persistent`: обновляем значение, помечаем dirty; `flush()`/async-задача →
  `encode` → `save` (батчем) → один `commit`.
- **Асинхронность (будущее):** `load`/`save`/`commit` — блокирующие операции с ожиданием;
  в будущем станут `async fn` (Tokio/Embassy).

## Требования

### 1. Типизированные значения вместо сырых байт

Сервер хранит ссылки на конкретные типы (`Codec`), а не A-XDR байты. Значение
кодируется/декодируется по требованию через `put`/`assign`/`stream_sink`.

### 2. Три класса данных + права доступа

- **Статичные (read-only):** `AttrKind::Static(&'static dyn Codec)` — указатель в ROM.
- **Динамические:** `AttrKind::Dynamic(slot)` — меняет только сервер, значение в RAM-слоте.
- **Настраиваемые (persistent):** `AttrKind::Persistent(slot)` — SET извне + NVM, значение в RAM-слоте.
- Уровни доступа (Public/Reader/Configurator/…) — битовой маской `Access`.

## Следующие шаги

См. также [TODO.md](../TODO.md).

- NVM-бэкенд: dirty-трекинг + `flush()`/async-задача (load/flush/commit), реализация под железо.
- Асинхронный NVM: `load`/`save`/`commit` → `async fn` (Tokio / Embassy).
- Диспетчеризация ACTION в цикле обслуживания (GET/SET уже разобраны).
- Методы объектов (Blue Book) с отдельными правами.
- Тесты на реальных A-XDR значениях (octet-string, visible-string, compact-array).
- HLS pass 3/4: `ActionRequest`/`ActionResponse` APDU в `cosempdu` + метод
  `reply_to_HLS_authentication` (Association LN, method_id 1).
- ECDSA-верификация подписи (заглушка → реальный крипто-бэкенд, P-256/P-384).

## Сделано

- Обработка GET-запросов: `Get-Request` → `handle_get` → `Get-Response` (`process_request`).
- Обработка SET-запросов: `Set-Request::Normal` → `process_set` → `stream_set` → `Set-Response`.
- Поточный SET в `Persistent`: `stream_set` → `StreamDecoder` → `StreamSink`.
- `#![no_std]` на крейте `server` (`#![cfg_attr(not(feature = "std"), no_std)]`).
- Модель конкурентности: `Session` (с буферами `rx`/`tx`) принадлежит вызывающему.
- Диспетчеризация `process_request` работает с `Option<usize>`: `Some(n)` — в `tx`
  лежит `n`-байтовый APDU ответа, `None` — APDU **отброшен** (`send = false`),
  сессия продолжается. `Err` остаётся только для уровня WPDU/буфера
  (`Tag::get`, `validate_wrapper`, `tx.set_pos`, `tx.write_at`): содержимое APDU
  соединение больше не рвёт.
  Для xDLMS-сервисов ошибка типизирована (`RequestError`):
  `NotWellFormed` → `exception-response (service-unknown, operation-not-possible)`,
  `NotSupported` (WithList/NextPblock/access_selection/неизвестный class_id) →
  `exception-response (service-not-allowed, service-not-supported)` — обе строки из
  Table 89; `Internal(Error)` (сбой кодирования/инварианта) — единственный случай,
  который завершает сессию. Хелперы `build_exception_response` /
  `build_association_not_established` возвращают `Option<usize>`.
- Интеграция ACSE/BER: `process_request` (AARQ → AARE, RLRQ → RLRE); подавление
  AARE при `response_allowed=false` (`process_request` → `bool`).
  AARQ (`process_aarq`): возвращает `(Option<usize>, bool)` (`Some(n)` — AARE в tx,
  `None` — APDU отброшен, как в release). Неразбираемый AARQ **отбрасывается** —
  по 9.3.2 `.indication` генерится только для корректного AARQ, а AARE должен
  echo-ить `application-context-name`, который из битого APDU не достать.
  Отсутствующий/битый `user-information` (нет xDLMS InitiateRequest) — это
  «AARQ syntax is not acceptable» (9.4.4.1): `AARE(rejected-permanent,
  acse-service-provider / no-reason-given)`. AARQ при уже существующей AA
  разбирается выше по диспетчеру как `exception-response` — разрешённый 9.4.4.2
  «optional» вариант. Инвариант состояния: **только принятая ассоциация оставляет
  наговорённые параметры в `Settings`**; любой отказ или отброс сбрасывает их
  через `Settings::new()` (`reject_aarq`), поэтому сессия остаётся чистой и
  готова к повторному AARQ. Ошибок (`Err`) в AARQ-пути больше нет — сбой
  кодирования AARE даёт `None` + `debug_assert!`. В HLS-ветке (`ecdsa_*`) AARE
  кодируется **до** захвата скретча `HLS_HANDSHAKE`, чтобы сбой не залипил его для
  следующих ассоциаций.
  Release — без `Result`: `handle_release` возвращает `Option<usize>` (`Some` — RLRE
  в tx и переход в `Disconnecting`; `None` — ответа нет, `send = false`,
  состояние не меняется, т. е. APDU отброшен). Неразбираемый RLRQ (битый BER / не
  RLRQ) молча отбрасывается и AA сохраняется (9.3.3: без `.indication` release не
  начинается). Так же обрабатывается невозможность закодировать RLRE (при
  `RX_BUF = 1032` и 5 байтах ответа это недостижимо — стоит `debug_assert!`):
  состояние фиксируется только после успешного `put`, поэтому «полу-перехода» нет,
  а release клиент подтверждает сам по таймауту (9.3.3 перечисляет этот вариант
  `.confirm`).
- Compile-time каталоги: `merge_objects`/`objects!` (сортировка объектов по OBIS,
  бинарный поиск в `find_object`) и `merge_attrs` (резолв OBIS→индекс объекта +
  сортировка атрибутов по [`AttrKey`]).
- Дефолты в `server`: `LDN_OBJ`/`LDN_OBIS`/`LDN_ATTR_DESC`/`OBJECTS`/`ATTRS`,
  `init_ldn_base()`/`init_server_system_title()`, а также объект Security setup
  (`SECURITY_SETUP_OBJ`, OBIS `0.0.43.0.1.255`) с атрибутами `security_suite`
  (attr 3, Static) и `server_system_title` (attr 5, Dynamic).
- `DedicatedKey` (`None`/`Aes128`/`Aes256` за фичами `aes128`/`aes256`) в `Settings`.
- `init_mutable_defaults()`: слот 0 — базовый LDN, слот 1 — server-system-title,
  слоты 2–3 — секреты LLS ассоциаций reader/configurator (attr 7,
  `Persistent`, дефолт «ABCDEFGH»). Public-ассоциация анонимная (attr 6 = 0),
  секрета у неё нет.
- `authentication_mechanism_name` (attr 6) задан статически: public — `0`
  (без аутентификации), reader — `1` (LLS), configurator — `2` (HLS).
  В `process_aarq` механизм из AARQ сверяется с attr 6 по уровню
  (0 / 1 / 2…7); при отсутствии механизма для аутентифицирующей ассоциации →
  `authentication-mechanism-name-required`, при несовпадении уровней →
  `authentication-mechanism-name-not-recognised`.
- LLS-аутентификация (AARQ): диспетчеризация по `mechanism-name` через `match`;
  для `LowLevelSecurity` пароль из `calling-authentication-value` сверяется с
  `secret` (attr 7) выбранной ассоциации (`Settings.assoc_idx` → `attr_codec`);
  несовпадение → `RejectedPermanent` + `authentication-failure`. Секрет — `Persistent`;
  тип доступа — `AuthenticatedReadOnly` только для «своего» уровня
  (`reader` — для reader-секрета, `configurator` — для configurator-секрета),
  остальным — `NoAccess` (public — анонимный, секрета у него нет). Изменение
  секрета — через ACTION-метод `change_HLS_secret` (method 2), не через SET.
- Action-Request (`[195]`, только `normal`): доступ и состав методов — декларативные.
  `METHODS` ([`MethodSpec`]: OBIS + method_id + `MethodAccess`) резолвится
  `merge_methods` в ROM-таблицу `MethodDesc` (индекс объекта + method_id +
  права); `Server::with_methods(&METHODS)` подключает её. `handle_action`
  ищет запись бинарным поиском, проверяет `MethodAccess::can_call(settings)`
  (per-SAP + authenticated) и затем `match` по `(class_id, method_id)`
  вызывает отдельный обработчик (`server/src/methods.rs`). `object_list`
  строится из этой же таблицы с фильтром по SAP (как атрибуты).
  Для Association LN реализован метод 2 `change_HLS_secret` — параметры
  `octet-string` (или `structure { octet-string }`) записываются прямо в `secret`
  (attr 7). Результат — типизированный `cosempdu::apdu::ActionResult`
  (ENUMERATED; номера совпадают с `DataAccessResult`, ACTION-специфичные —
  `long-action-aborted (15)` / `no-long-action-in-progress (16)`). Ошибки
  `find_object` возвращаются узким `FindObjectError` и конвертируются в
  `ActionResult` через `From`.
  Контракт обработчика — `ActionOutcome = Result<(), ActionResult>`:
  `Ok(())` = `success (0)`, `Err(result)` = метод не выполнен, причина уходит
  клиенту. Ошибок транспорта/кодека здесь нет (APDU разобран выше), а
  `hardware-fault` зарезервирован за дефектами конфигурации сервера
  (кодек без потока, отсутствующий слот), тогда как битые параметры клиента —
  всегда `type-unmatched (12)`; сессия из-за них не рвётся. Этим же типом
  возвращает и сам `handle_action` (ошибка `find_object` конвертируется `?` через
  `From<FindObjectError> for ActionResult`); `action_result` превращает исход
  в `ActionResult` для `Action-Response`. Согласованность реестра и
  диспетчера закреплена: `has_handler(class_id, method_id)` перечисляет пары,
  для которых есть обработчик, а тест `every_registry_method_has_handler`
  ловит запись в `METHODS` без обработчика (тогда клиент получил бы метод в
  `object_list`, но `hardware-fault` на вызов).
- `security_suite` (для dedicated key при шифровании) теперь data-driven:
  `Server::security_suite()` читает `security_setup_reference` (attr 9) ассоциации
  (через `Server::security_setup_reference(assoc_idx)`), находит по OBIS объект
  Security setup (class_id 64) и читает его `security_suite` (attr 3).
  Отсутствие ссылки (LLS, reader) → fallback `AesGcm128`.
- Security setup — общий (shared) объект: он доступен только той ассоциации,
  которая ссылается на него через `security_setup_reference` (attr 9).
  Ограничение «одна ассоциация на уровень клиента» позволяет выразить это
  обычным механизмом `Access`: у него используются константы `SHARED_READ` /
  `SHARED_WRITE` (configurator — `ReadOnly`/`WriteOnly`, public и reader —
  `NoAccess`). Отдельной рантайм-проверки на уровне объекта нет; GET/SET
  проверяют права как обычно (`desc.access.can_read/can_write`).
  `security_setup_reference` остаётся нужен только внутреннему пути
  (`Server::security_suite()` при AARQ) и не участвует в проверке доступа.
- Видимость объекта — единое правило (`Server::object_visible(index, sap)`):
  объект виден уровню, если у него есть хотя бы один атрибут (кроме неявного
  `logical_name`) или метод с не-`NoAccess`. Оно же решает состав `object_list`
  (`ServerObjectList::visible`), и оно же закрывает чтение `logical_name` (attr 1)
  у невидимых объектов — GET отвечает `scope-of-access-violated`.
  Поэтому Security setup попадает только в список configurator (5 объектов
  у reader/public, 6 — у configurator).
- `xDLMS_context_info` (Association LN, attr 5) не хранится, а вычисляется при GET:
  `AttrKind::Computed`/`RomKind::Computed` — пустой маркер (без fn-указателя и
  RAM-слота); дескрипторы остаются в `ATTRS` только ради `Access` (для будущего
  `object_list`). Диспетчеризация — в `Server::lookup_value` (единая точка по
  `RomKind`): `Computed`-arm делает O(1)-`match` по `class_id` + `attribute_id` +
  OBIS и возвращает owned `GetValue::Computed`. Доступны базовый OBIS `0.0.40.0.0.255`
  (объект `ASSOC_LN_BASE` — alias текущей ассоциации) и OBIS текущей ассоциации
  (`Server::assoc_obis(assoc_idx)`); чужая ассоциация получает `ReadWriteDenied`.
  Разрешение alias живёт в `Server::resolve_alias(class_id, obis, assoc_idx)` и
  применяется единообразно в GET (`lookup_value`), SET (`stream_set`) и ACTION
  (`handle_action`): подменяется только адрес поиска, а `logical_name` (attr 1)
  по-прежнему возвращает запрошенный OBIS (alias остаётся alias-ом).
  Без выбранной ассоциации (`assoc_idx == u8::MAX`) alias не разрешается.
  Значение — owned `XdlmsContextInfoValue` (`conformance: bit-string`,
  `max_receive_pdu_size`, `max_send_pdu_size`, `dlms_version_number`,
  `quality_of_service = 0`, `cyphering_info`). Conformance
  сервера — константа `PROPOSED_CONFORMANCE` (одинакова для всех ассоциаций); поле
  `Server.proposed_conformance` удалено, AARQ пересекает `req.proposed_conformance`
  с `PROPOSED_CONFORMANCE`.
- Валидация AARQ: `calling-AP-title` → `system_title_c`; при шифровании
  calling-AP-title обязателен (иначе acse-service-provider: no-reason-given);
  `called-AP-title` при наличии сверяется с server-system-title.
- HLS 4-pass (pass 1/2 в AARQ/AARE): CtoS/StoC в authentication-value,
  сертификат в `calling-AE-qualifier`; скретч `HlsHandshake` + `CallingAeQualifier`;
  pass 3/4 через ACTION `reply_to_HLS_authentication` — follow-up.
- Фича-gating полей `AARQapdu`: `calling_ae_qualifier` ← ecdsa,
  `calling_ae_invocation_id` ← `association_ln_v2`.

## Открытые вопросы

- `is_digitally_signed()` (вывести из `security_suite` suites 1/2) — заглушка.
- Конкурентный доступ к мутабельным значениям (сейчас — единственный `&mut` на слот).
- Кодирование «HLS success (0x0E)» в AARE pass 2 (предположительно
  `authentication-required` 14) — подтвердить.
- StoC — RNG (сейчас константа); таймаут скретча, если клиент не пришлёт pass 3.
- Содержимое `calling-AE-qualifier` (только открытый ключ vs system-title||key).
- Назначение/тип `calling-AE-invocation-id` (Association LN v2+).

## Связанные документы

- [GBT и object_list](gbt_object_list.md) — блочная передача computed и формирование Association LN `object_list`
- [Data](data.md) — COSEM Data types
- [APDU](apdu.md) — COSEM APDU
- [ACSE](acse.md) — ACSE APDU (транспорт)
- [Buffer](buffer.md) — буферы для работы с байтами
