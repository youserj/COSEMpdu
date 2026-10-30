# TODO

Дальнейшие шаги для сервера DLMS/COSEM (крейт `server`).

## Ближайшие шаги

- [ ] **NVM-бэкенд.** Трейт `Nvm` (`load`/`save`/`commit`); dirty-трекинг,
      `flush()`/async-задача: `put` → `save` (батчем) → один `commit`;
      загрузка Persistent на старте, восстановление из заводского дефолта
      (`AttributeInfo.default`). Реализация под железо — позже.
- [ ] **Асинхронный NVM.** `load`/`save`/`commit` станут `async fn` — Tokio
      (desktop) / Embassy (embedded).
- [ ] **Диспетчеризация SET/ACTION.** В цикле обслуживания разобран только GET;
      `Set-Request` (через `stream_set`) и `Action-Request` ещё не привязаны.
- [ ] **Методы объектов.** Диспетчеризация методов (Blue Book) с отдельными
      правами на методы — сейчас отложено.
- [ ] **Тесты на реальных A-XDR значениях** (octet-string, visible-string,
      compact-array).

## Сделано

- [x] **Интеграция `dlms1` ↔ `server`.** `dlms1` даёт статические дескрипторы
      объектов (`InterfaceClass`: `class_id`/`version`/`obis`/`attributes`);
      `server` хранит атрибуты по отдельности (`Attribute` + `ValueRef`, ключ
      `ObisCode` + attribute_id) и валидирует входящие `class_id` + OBIS по
      статическому каталогу `OBJECTS`.
- [x] **Обработка GET-запросов.** `Get-Request` (Normal) → `handle_get` →
      `Get-Response`; декодирование в owned-поля, `get_codec` + проверка `read`.
- [x] **Поточный SET в `Persistent`.** `stream_set` → `StreamDecoder` → `StreamSink`.
- [x] **`#![no_std]` для крейта `server`.** `#![cfg_attr(not(feature = "std"), no_std)]`.
- [x] **Модель конкурентности.** `Session` (с буферами `rx`/`tx`) принадлежит
      вызывающему; `Server` владеет только реестром/каталогом/пулами.
- [x] **Интеграция ACSE/BER транспорта.** `accept_association`/`process_request`
      (AARQ → AARE, RLRQ → RLRE) поверх Wrapper (tcp/ble).


