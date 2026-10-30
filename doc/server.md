# План реализации сервера (DLMS/COSEM Server)

> Рабочий документ. Здесь фиксируются требования и проектные решения к
> серверной части, построенной поверх модулей `cosempdu` (ACSE + xDLMS APDU).
> Требования дополняются по мере появления.

## Обзор

Сервер принимает входящие APDU (GET/SET/ACTION), хранит COSEM-объекты и их
атрибуты, формирует ответные APDU. Транспорт — BER-сессия ACSE, вложенный
полезный груз — xDLMS APDU (A-XDR).

Подход к хранению — **типизированные значения** + **права доступа**. Сервер
хранит ссылки на конкретные типы (реализующие `cosempdu::Codec`), которые сами
кодируются (`put`) и декодируются (`assign`/`stream_sink`), а также несут права
доступа ([`Access`]).

## Модель данных (реализовано в `server/src/lib.rs`)

```rust
pub const MAX_ATTRS: usize = 1024;   // ёмкость реестра

/// Битовая маска уровней доступа (каждый уровень — свой бит).
pub struct AccessMask(pub u8);
// AccessMask::PUBLIC / READER / CONFIGURATOR; приложение добавляет свои: AccessMask(1 << n)
// contains(mask) -> bool, BitOr для объединения

/// Права доступа к атрибуту.
pub struct Access {
    pub read: AccessMask,   // уровни, которым разрешено чтение (GET)
    pub write: AccessMask,  // уровни, которым разрешена запись (SET; только Persistent)
}

/// Объектно-безопасный кодек типизированного значения (в `cosempdu`).
pub trait Codec {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize, Error>;           // encode
    fn assign(&mut self, data: &Data<'_>) -> Result<(), Error>;                // decode из Data (update)
    fn stream_sink(&mut self) -> Option<&mut dyn StreamSink>;                  // decode из байт (stream_set)
    fn get<'a>(buf, arena) -> Result<Self, Error> where Self: Sized + Default;  // decode целиком
}

pub struct AttributeKey {            // ключ = OBIS + attribute_id (class_id не нужен)
    pub instance_id: [u8; 6],
    pub attribute_id: u8,
}

pub enum ValueRef<'a> {
    Static(&'a dyn Codec, Access),          // read-only
    Dynamic(&'a mut dyn Codec, Access),     // меняет только сервер
    Persistent(&'a mut dyn Codec, Access),  // SET извне + NVM
}

pub struct Registry<'a> { /* отсортированный массив (AttributeKey, ValueRef<'a>) + бинарный поиск */ }

pub struct Server<'a, const N: usize = 3> {
    // каталог COSEM-объектов + реестр атрибутов + conformance + пулы-счётчики
    // (лимит N); буферы соединения — НЕ здесь, а в `Session` (см. «Транспорт и сессии»)
}

impl<'a, const N: usize> Server<'a, N> {
    pub fn add_static(&mut self, key, attr: &'a dyn Codec, access: Access) -> Result<(), Error>;
    pub fn add_dynamic(&mut self, key, attr: &'a mut dyn Codec, access: Access) -> Result<(), Error>;
    pub fn add_persistent(&mut self, key, attr: &'a mut dyn Codec, access: Access) -> Result<(), Error>;
    pub fn put(&self, class_id: ClassId, key: AttributeKey, level: AccessMask, buf: &mut ByteBuffer<'_>) -> Result<(), Error>; // put → buf (проверка read)
    pub fn stream_set(&mut self, class_id: ClassId, key: AttributeKey, level: AccessMask) -> Result<StreamingSet, Error>;      // stream → Persistent (проверка write)
    pub fn update(&mut self, key: AttributeKey, data: &Data<'_>) -> Result<(), Error>;                                       // assign → Dynamic (внутреннее)
}
```

- Реестр — фиксированный массив `[Option<(AttributeKey, ValueRef<'a>)>; MAX_ATTRS]`,
  отсортирован по ключу, поиск — `binary_search_by` (O(log n)). Вставка нового
  ключа — O(n) сдвиг (редкая операция).
- Нет байтового пула: тип сам кодирует/декодирует/валидирует.
- `ValueRef` хранит `&mut dyn Codec` → не `Copy`; `Server`/`Registry` с lifetime
  `'a`; `new()` не `const fn` (инициализация через `from_fn`). Для embedded — объекты
  `static`, сервер создаётся в `main` (`&mut` на static-объекты).
- Куча не используется (no-heap, готово к `no_std`).

## Уровни доступа (битовая маска)

Уровни (Public, Reader, Configurator, …) **не пересекаются**, поэтому доступ задаётся
набором бит, а не порогом:

- `AccessMask(pub u8)` — каждый уровень свой бит; `contains(mask)` — есть ли пересечение.
- `Access { read, write }` — наборы уровней для чтения и записи.
- `put(key, level, buf)` проверяет `access.read.contains(level)`, `set(key, level, data)` —
  `access.write.contains(level)`; нарушение → `Error::AccessDenied`.

Пример: атрибут читают Public и Configurator (но не Reader), пишет только Configurator:

```rust
let acc = Access {
    read: AccessMask::PUBLIC | AccessMask::CONFIGURATOR,
    write: AccessMask::CONFIGURATOR,
};
server.add_persistent(key, &mut register, acc)?;
// put(key, PUBLIC, buf)  -> Ok
// put(key, READER, buf)  -> AccessDenied
// set(key, CONFIGURATOR, d) -> Ok
// set(key, PUBLIC, d)       -> AccessDenied
```

## Поток данных

- **Клиент → сервер (SET):** клиент подаёт A-XDR байты в `stream_set` → `StreamDecoder`
  декодирует прямо в атрибут через `StreamSink` (проверка `write`). Буферный путь
  (`Data` целиком) не используется.
- **Сервер → клиент (PUT):** `put(key, level, buf)` → проверка `read` → `put` в `ByteBuffer`.
- `Dynamic` сервер меняет сам (`update` из готового `Data`, без уровня), отдаётся через `put`.

## Транспорт и сессии

Соединение обслуживает **`Session`** — значение с буферами `rx`/`tx` и состоянием
транспорта (`media`, `transport_ref`, `conformance`, `state`, `invoke_id`).
**`Session` принадлежит вызывающему** (задаче соединения или `serve`), а не
`Server`. Поэтому I/O канала читает/пишет в `session.rx`/`session.tx` и **не
требует `&mut Server`** — мьютекс нужен только на короткую фазу разбора/кодирования.

`Server` хранит только каталог объектов, реестр атрибутов, `proposed_conformance`
и пулы-счётчики транспортных слотов (лимит `N`).

```rust
impl<'a, const N: usize> Server<'a, N> {
    // Жизненный цикл соединения
    pub fn on_connect(&mut self, media: Media) -> Result<Session, Error>;   // занять слот → Session
    pub fn on_disconnect(&mut self, media: Media);                          // освободить слот

    // DLMS-слой (без сетевого I/O — читают session.rx, пишут session.tx)
    pub fn accept_association(&self, session: &mut Session, received: Wrapper) -> Result<(), Error>; // AARQ → AARE + state=Associated
    pub fn process_request(&mut self, session: &mut Session, received: Wrapper) -> Result<bool, Error>; // AARQ/Get/Set/RLRQ

    // Get-Request (Normal) → Get-Response; принимает декодированные owned-поля
    pub fn handle_get(&self, invoke: InvokeIdAndPriority, descriptor: CosemAttributeDescriptor, buf: &mut ByteBuffer<'_>) -> Result<usize, Error>;

    // Весь цикл соединения (AARQ/AARE, GET/SET, RLRQ — через process_request)
    pub async fn serve<C: Channel<Frame = Wrapper>>(&mut self, media: Media, channel: C) -> Result<(), Error>;
}
```

Поток на одно соединение:

```
on_connect(media) -> Session
      │
      ▼  (цикл обслуживания: read → process → write)
channel.read(session.rx_mut())
process_request(session, received)    // AARQ → AARE / Get / Set / RLRQ в session.tx
channel.write(session.tx())
      │  … до RLRQ/таймаута/закрытия/ошибки
      ▼
on_disconnect(media)
```

- Валидация Wrapper-заголовка (`validate_wrapper`) выполняется внутри
  `accept_association` (вызывается из `process_request` для AARQ) и обновляет
  порты в `session`; после успешной ассоциации `Session.state = Associated`.
- `handle_get` декодирует `Get-Request` в owned-`Copy` поля (`InvokeIdAndPriority`,
  `CosemAttributeDescriptor`) — ссылка на буфер приёма гаснет сразу, поэтому можно
  одновременно держать `&mut Session` и `&self Server`.
- `serve` — обёртка `on_connect` → цикл (приватный `handle_request`, включая AARQ)
  → `on_disconnect` для однопоточного embedded-сценария. `tcp-pc-server` вместо неё
  делает read/process/write вручную, не удерживая мьютекс на I/O.

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

- **Статичные (read-only):** `ValueRef::Static(&'a dyn Codec, Access)`.
- **Динамические:** `ValueRef::Dynamic(&'a mut dyn Codec, Access)` — меняет только сервер.
- **Настраиваемые (persistent):** `ValueRef::Persistent(&'a mut dyn Codec, Access)` — SET извне + NVM.
- Уровни доступа (Public/Reader/Configurator/…) — битовой маской `Access`.

## Следующие шаги

См. также [TODO.md](../TODO.md).

- NVM-бэкенд: dirty-трекинг + `flush()`/async-задача (load/flush/commit), реализация под железо.
- Асинхронный NVM: `load`/`save`/`commit` → `async fn` (Tokio / Embassy).
- Диспетчеризация SET/ACTION в цикле обслуживания (сейчас разобран только GET).
- Методы объектов (Blue Book) с отдельными правами.
- Тесты на реальных A-XDR значениях (octet-string, visible-string, compact-array).

## Сделано

- Обработка GET-запросов: `Get-Request` → `handle_get` → `Get-Response` (`process_request`).
- Поточный SET в `Persistent`: `stream_set` → `StreamDecoder` → `StreamSink`.
- `#![no_std]` на крейте `server` (`#![cfg_attr(not(feature = "std"), no_std)]`).
- Модель конкурентности: `Session` (с буферами `rx`/`tx`) принадлежит вызывающему.
- Интеграция ACSE/BER: `accept_association`/`process_request` (AARQ → AARE, RLRQ → RLRE).

## Открытые вопросы

- Полный SET-диспетч: `stream_set` есть, но разбор `Set-Request` в цикле ещё не привязан.
- Несколько `ValueRef` на атрибут, если потребуется конкурентный доступ к реестру (сейчас — один).

## Связанные документы

- [Data](data.md) — COSEM Data types
- [APDU](apdu.md) — COSEM APDU
- [ACSE](acse.md) — ACSE APDU (транспорт)
- [Buffer](buffer.md) — буферы для работы с байтами
