# План реализации сервера (DLMS/COSEM Server)

> Рабочий документ. Здесь фиксируются требования и проектные решения к
> серверной части, построенной поверх модулей `cosempdu` (ACSE + xDLMS APDU).
> Требования дополняются по мере появления.

## Обзор

Сервер принимает входящие APDU (GET/SET/ACTION), хранит COSEM-объекты и их
атрибуты, формирует ответные APDU. Транспорт — BER-сессия ACSE, вложенный
полезный груз — xDLMS APDU (A-XDR).

Подход к хранению — **типизированные значения** + **права доступа**. Сервер
хранит ссылки на конкретные типы (реализующие [`Attribute`]), которые сами
кодируются (`put`) и декодируются (`assign`), а также несут права доступа
([`Access`]).

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

/// Объектно-безопасный интерфейс типизированного значения.
pub trait Attribute {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> Result<usize, Error>;
    fn assign(&mut self, data: &Data<'_>) -> Result<(), Error>;
}

pub struct AttributeKey {            // ключ = OBIS + attribute_id (class_id не нужен)
    pub instance_id: [u8; 6],
    pub attribute_id: u8,
}

pub enum ValueRef<'a> {
    Static(&'a dyn Attribute, Access),          // read-only
    Dynamic(&'a mut dyn Attribute, Access),     // меняет только сервер
    Persistent(&'a mut dyn Attribute, Access),  // SET извне + NVM
}

pub struct Registry<'a> { /* отсортированный массив (AttributeKey, ValueRef<'a>) + бинарный поиск */ }

pub struct Server<'a> { pub attributes: Registry<'a> }

impl<'a> Server<'a> {
    pub fn add_static(&mut self, key, attr: &'a dyn Attribute, access: Access) -> Result<(), Error>;
    pub fn add_dynamic(&mut self, key, attr: &'a mut dyn Attribute, access: Access) -> Result<(), Error>;
    pub fn add_persistent(&mut self, key, attr: &'a mut dyn Attribute, access: Access) -> Result<(), Error>;
    pub fn put(&self, class_id: ClassId, key: AttributeKey, level: AccessMask, buf: &mut ByteBuffer<'_>) -> Result<(), Error>; // put → buf (проверка read)
    pub fn set(&mut self, class_id: ClassId, key: AttributeKey, level: AccessMask, data: &Data<'_>) -> Result<(), Error>;      // assign → Persistent (проверка write)
    pub fn update(&mut self, key: AttributeKey, data: &Data<'_>) -> Result<(), Error>;                                       // assign → Dynamic (внутреннее)
}
```

- Реестр — фиксированный массив `[Option<(AttributeKey, ValueRef<'a>)>; MAX_ATTRS]`,
  отсортирован по ключу, поиск — `binary_search_by` (O(log n)). Вставка нового
  ключа — O(n) сдвиг (редкая операция).
- Нет байтового пула: тип сам кодирует/декодирует/валидирует.
- `ValueRef` хранит `&mut dyn Attribute` → не `Copy`; `Server`/`Registry` с lifetime
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

- **Клиент → сервер (SET):** клиент кладёт A-XDR в `ByteBuffer`, сервер декодирует в
  `Data`, затем `set(key, level, &data)` → проверка `write` → `assign` обновляет `Persistent`.
- **Сервер → клиент (PUT):** `put(key, level, buf)` → проверка `read` → `put` в `ByteBuffer`.
- `Dynamic` сервер меняет сам (`update`, без уровня), всё значение отдаётся через `put`.

## Валидация и восстановление

- `assign` — декодирует `Data` в конкретный тип и проверяет его (тег для базы,
  `recast`/`FromStructure` для структур). Не тот тип → `Error::TypeMismatch`.
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
- `set` на `Persistent`: обновляем значение, помечаем dirty; `flush()`/async-задача →
  `encode` → `save` (батчем) → один `commit`.
- **Асинхронность (будущее):** `load`/`save`/`commit` — блокирующие операции с ожиданием;
  в будущем станут `async fn` (Tokio/Embassy).

## Требования

### 1. Типизированные значения вместо сырых байт

Сервер хранит ссылки на конкретные типы (`Attribute`), а не A-XDR байты. Значение
кодируется/декодируется по требованию через `encode`/`assign`.

### 2. Три класса данных + права доступа

- **Статичные (read-only):** `ValueRef::Static(&'a dyn Attribute, Access)`.
- **Динамические:** `ValueRef::Dynamic(&'a mut dyn Attribute, Access)` — меняет только сервер.
- **Настраиваемые (persistent):** `ValueRef::Persistent(&'a mut dyn Attribute, Access)` — SET извне + NVM.
- Уровни доступа (Public/Reader/Configurator/…) — битовой маской `Access`.

## Следующие шаги

См. также [TODO.md](../TODO.md).

- NVM-бэкенд: dirty-трекинг + `flush()`/async-задача (load/flush/commit), реализация под железо.
- Асинхронный NVM: `load`/`save`/`commit` → `async fn` (Tokio / Embassy).
- Обработка GET/SET-запросов: привязать `cosempdu::apdu` к `Server`.
- Объявить `#![no_std]` на крейте `server`.
- Модель конкурентности (несколько соединений → несколько буферов обмена).
- Интеграция ACSE/BER транспорта.

## Открытые вопросы

- Модель конкурентности: однопоточный `&mut self` vs несколько буферов обмена.
- Несколько соединений → несколько буферов обмена (и, вероятно, несколько `ValueRef`).

## Связанные документы

- [Data](data.md) — COSEM Data types
- [APDU](apdu.md) — COSEM APDU
- [ACSE](acse.md) — ACSE APDU (транспорт)
- [Buffer](buffer.md) — буферы для работы с байтами
