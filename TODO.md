# TODO

Дальнейшие шаги для сервера DLMS/COSEM (крейт `server`).

## Ближайшие шаги

- [ ] **NVM-бэкенд.** Трейт `Nvm` (`load`/`save`/`commit`); dirty-трекинг,
      `flush()`/async-задача: `put` → `save` (батчем) → один `commit`;
      загрузка Persistent на старте, восстановление из заводского дефолта
      (`AttributeInfo.default`). Реализация под железо — позже.
- [ ] **Асинхронный NVM.** `load`/`save`/`commit` станут `async fn` — Tokio
      (desktop) / Embassy (embedded).
- [ ] **Обработка GET/SET-запросов.** Привязать `cosempdu::apdu`
      (`GetRequest`/`SetRequest`) к `Server`: разбор → `ClassId` + `ObisCode` +
      attribute_id → `put`/`set` → ответный APDU.
- [ ] **Методы объектов.** Диспетчеризация методов (Blue Book) с отдельными
      правами на методы — сейчас отложено.
- [ ] **`#![no_std]` для крейта `server`.** Код уже готов (только `core`).
- [ ] **Модель конкурентности.** Несколько соединений → несколько буферов
      обмена (и, вероятно, несколько `ValueRef`).
- [ ] **Интеграция ACSE/BER транспорта.**
- [ ] **Тесты на реальных A-XDR значениях** (octet-string, visible-string,
      compact-array).

## Сделано

- [x] **Интеграция `dlms1` ↔ `server`.** `dlms1` даёт статические дескрипторы
      объектов (`InterfaceClass`: `class_id`/`version`/`obis`/`attributes`);
      `server` хранит атрибуты по отдельности (`Attribute` + `ValueRef`, ключ
      `ObisCode` + attribute_id) и валидирует входящие `class_id` + OBIS по
      статическому каталогу `OBJECTS`.


