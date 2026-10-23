# Stream — поточный A-XDR декодер (`cosempdu::stream`)

> Push-парсер, который декодирует одно COSEM-значение ([`Data`]) из A-XDR
> (IEC 61334-6) по мере поступления байтов — **без буферизации всего значения**.
> Большие листья (octet-string, …) стримятся чанками прямо в [`StreamSink`].
>
> Используется сервером (`server::stream_set`) для поточного приёма SET-значений,
> в том числе сегментированных по APDU-блокам.

## Обзор

Обычное декодирование (`Data::get`) сначала собирает весь `Data` в памяти
(нужен `Arena`), а затем применяет его. Поточный декодер делает это **на лету**:

```
        A-XDR байты (чанками push)
                  │
                  ▼
        ┌───────────────────┐
        │   StreamDecoder   │   — состояние (State, стек композитов)
        └───────────────────┘
                  │  события
                  ▼
        ┌───────────────────┐
        │     StreamSink    │   — пишет прямо в поля атрибута
        └───────────────────┘
                  │
                  ▼
        типизированное значение (без промежуточного Data)
```

`StreamDecoder` — это конечный автомат; `StreamSink` — приёмник событий
(реализуется конкретным типом значения, например `RegisterAssignmentValue`).

## API

```rust
let mut dec = StreamDecoder::new(&mut sink);
dec.push(&chunk1)?;   // подать очередной кусок байт (сколько угодно раз)
dec.push(&chunk2)?;
dec.finish()?;        // завершить; ошибка, если значение неполно
```

Кусок можно резать **в любом месте** — между тегами, посреди длины, посреди
содержимого скаляра или blob'а. Декодер сам буферизует незавершённые элементы.

## Трейт `StreamSink`

| Метод | Событие | Параметры |
| ----- | ------- | --------- |
| `scalar(tag, bytes, index)` | фиксированный скаляр | `index` — индекс элемента во внешнем композите |
| `blob_begin(tag, len)` | начало blob'а (octet/visible/utf8-string) | `len` — полная длина |
| `blob_write(bytes, index, offset)` | чанк содержимого blob'а | `offset` — сколько байт уже доставлено |
| `blob_end()` | blob полностью принят | — |
| `composite_begin(tag, count)` | начало array/structure | `count` — число элементов |
| `composite_end()` | композит полностью принят | — |
| `finish()` | всё значение декодировано | — |

Методы, которые конкретная форма не использует, по умолчанию возвращают ошибку
(`UnexpectedScalar`/`UnexpectedBlob`/`UnexpectedComposite`). Поэтому скалярному
значению достаточно переопределить только `scalar`, а массиву структур — ещё
`composite_begin`/`blob_*`.

### Позиция (`index` / `offset`)

Раньше приёмнику приходилось хранить собственный курсор (индекс элемента,
смещение внутри blob'а). Теперь позицию передаёт **декодер**, поэтому приёмник
может быть «чистым» — просто массив, без полей-курсоров.

- `index` = индекс текущего элемента во **внешнем** композите
  (`totals[0] - stack[0]`; для top-level значения — `0`).
- `offset` = сколько байт текущего blob'а уже доставлено (`total - remaining`).

## Конечный автомат

Внутреннее состояние `State`:

```
                ┌──────────────────────────────┐
                │            Tag               │  ожидание тега
                └──────────────────────────────┘
                   │           │              │
        скаляр 0 байт   скаляр N байт   blob/композит
                   │           │              │
                   ▼           ▼              ▼
              [scalar()]   ┌───────┐     LengthFirst (1-й байт длины)
                   │       │Scalar │         │
                   ▼       │ (buf) │     < 0x80: короткая длина
              end_element  └───┬───┘     ≥ 0x80: LengthRest (длинная)
                   │        накопил size    │
                   │           │            │
                   │       [scalar()]       ▼
                   │           │       enter_len(tag, is_composite, len)
                   │       end_element      │
                   │               ┌────────┴─────────┐
                   │         composite            blob
                   │               │                 │
                   │       composite_begin        blob_begin
                   │               │                 │
                   │       stack.push(len)      ├─ len=0 → blob_end
                   │               │            └─ len>0 → Blob { total, remaining }
                   │               ▼                 │
                   │          State::Tag         [blob_write] (чанками)
                   │                                │
                   │                           remaining==0
                   │                                │
                   │                            [blob_end]
                   │                                │
                   └──────── end_element ◄──────────┘
```

`end_element()` — общая точка «элемент завершён»:

```
        stack пуст? ── да ──► State::Done
             │
             │ нет
        top > 1? ── да ──► top -= 1, State::Tag
             │
             │ нет (top == 1)
        pop(); composite_end();  // закрыли композит, повторяем цикл
```

Дополнительно хранятся:

- `stack: [usize; MAX_DEPTH]` — **оставшееся** число элементов на каждом уровне;
- `totals: [usize; MAX_DEPTH]` — **полное** число элементов (нужно для `index`);
- `stack_len` — текущая глубина вложенности (`MAX_DEPTH = 16`).

## A-XDR примитивы

Фиксированные скаляры (тег → размер в байтах):

| теги | размер |
|------|--------|
| 0, 255 | 0 |
| 3, 13, 15, 17, 22, 28, 31 | 1 |
| 16, 18, 29, 32 | 2 |
| 5, 6, 23, 27, 30, 33 | 4 |
| 26 | 5 |
| 20, 21, 24 | 8 |
| 25 | 12 |

Blob (длина-префикс): теги **9** (octet-string), **10** (visible-string), **12** (utf8-string).
Композиты: теги **1** (array), **2** (structure).

Длина: короткая форма — один байт `< 0x80`; длинная — первый байт `0x80 | n`
(число последующих байт `n`), затем `n` байт big-endian.

## Пример: `register_assignment` (array object_definition)

Значение — `array` из двух `structure { class_id: long-unsigned, logical_name: octet-string }`:

```
array {2}
├─ structure {2}
│   ├─ long-unsigned 3            (class_id = Register)
│   └─ octet-string 1.0.1.8.0.255
└─ structure {2}
    ├─ long-unsigned 4            (class_id = ExtendedRegister)
    └─ octet-string 1.0.2.8.0.255
```

A-XDR байты:

```
01 02 | 02 02 12 00 03 09 06 01 00 01 08 00 FF | 02 02 12 00 04 09 06 01 00 02 08 00 FF
──────┘ └──────────────────────────────────────┘ └──────────────────────────────────────┘
 array  структура #0                              структура #1
```

Декодер выдаёт события и позицию (приёмник = `[ObjectDefinition; N]`, пишет в `items[index]`):

```
байты        событие                                  index  offset
01           composite_begin(tag=1, count=2)          —      —
02           composite_begin(tag=2, count=2)          —      —
12 00 03     scalar(18, [00 03], index=0)             0      —   → items[0].class_id = 3
09           blob_begin(tag=9, len=6)                 —      —
01 00 01 08 00 FF
             blob_write([01 00 01 08 00 FF], 0, 0)    0      0   → items[0].logical_name[0..6]
             blob_end()                               —      —   (структура #0 закрыта)
02 02        composite_begin(tag=2, count=2)          —      —
12 00 04     scalar(18, [00 04], index=1)             1      —   → items[1].class_id = 4
09 06 01 00 02 08 00 FF
             blob_write([01 00 02 08 00 FF], 1, 0)    1      0   → items[1].logical_name[0..6]
             blob_end()                               —      —
             composite_end()                          —      —   (array закрыт)
             finish()                                 —      —   → готово
```

Здесь `index` — это индекс структуры внутри массива (`totals[0] - stack[0]`), а не
номер поля внутри структуры (его роль играет тег: `18` → class_id, `9` → logical_name).

### Разрыв по чанкам

Тот же поток, разрезанный произвольно (например, 3 куска по `n/3`):

```
push([01 02 02 02 12 00 03 09 06])   → composite_begin(1,2), composite_begin(2,2),
                                       scalar(18, …, 0), blob_begin(9, 6)
push([01 00 01 08 00 FF 02 02 12])   → blob_write([01 00 01 08 00 FF], 0, 0), blob_end,
                                       composite_begin(2,2)   (частично: тег 12)
push([00 04 09 06 01 00 02 08 00 FF])→ scalar(18, …, 1), blob_begin(9,6),
                                       blob_write([01 00 02 08 00 FF], 1, 0), blob_end
finish()                             → composite_end(), finish()
```

- Скаляр `long-unsigned` разрезан между тегом (в конце 2-го куска) и содержимым
  (в начале 3-го) — декодер накапливает его в `State::Scalar` и вызывает `scalar`
  **один раз**, когда оба байта собраны.
- Blob `octet-string` приходит целиком в одном `blob_write`, но если бы граница
  прошла посреди 6 байт — `blob_write` был бы вызван несколько раз, а `offset`
  подсказал бы, куда дописывать.

## Обработка ошибок

- `IncompleteValue` — `finish()` при незавершённом значении.
- `NestingTooDeep` — вложенность больше `MAX_DEPTH`.
- `UnexpectedScalar`/`UnexpectedBlob`/`UnexpectedComposite` — событие не подходит форме приёмника.
- `InputTooLarge` — blob/композит не влезает в буфер приёмника.

## Связь с сервером

`server::stream_set(class_id, key, level)` берёт `Codec::stream_sink()`, оборачивает
его в `StreamDecoder` и возвращает `StreamingSet` (`push`/`finish`). Это **единственный**
внешний путь записи в `Persistent`-атрибут; внутренние `Dynamic`-обновления идут через
`assign` (см. [server.md](server.md)).

## Связанные документы

- [data](data.md) — COSEM Data types и A-XDR кодирование (`Data::put`/`Data::get`).
- [axdr](axdr.md) — A-XDR примитивы.
- [server](server.md) — сервер, использующий поточный декодер.

