//! Минимальный DLMS/COSEM сервер (реестр атрибутов + каталог объектов).
//!
//! Атрибуты хранятся **по отдельности** — типизированные значения [`Attribute`],
//! права доступа [`Access`] и вид изменяемости ([`ValueRef`]). Поэтому каждый
//! атрибут размещается в памяти независимо (`static` → ROM, `static mut` → RAM).
//! Каталог COSEM-объектов ([`InterfaceClass`]) хранится в сервере как
//! `static`-срез и используется для валидации входящих запросов
//! (`class_id` + OBIS). Куча не используется (no-heap, готово к `no_std`).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate std;

use core::fmt;

use cosempdu::apdu::{GetDataResultWrite, GetRequest, GetResponse};
use cosempdu::apdu_sn::Conformance;
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::{Codec, Data};
use cosempdu::stream::{StreamDecoder, StreamSink};
use dlms1::ic::{AttributeKey, ClassId, InterfaceClass};
use dlms1::obis::ObisCode;

#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::acse::{AAREapdu, ACSEApdu};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::apdu_sn::{InitiateRequest, InitiateResponse, ObjectName};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::buffer::Reader;

mod channel;
mod session;
mod transport;

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub use session::{AssociationState, Session, RX_BUF};

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub use transport::{Media, TransportRef, MAX_APDU, TRANSPORT_OVERHEAD};

#[cfg(feature = "optical")]
pub use transport::{HdlcPool, HdlcState};

#[cfg(any(feature = "tcp", feature = "ble"))]
pub use transport::{Wrapper, WrapperPool, WrapperSetting, WRAPPER_VERSION};

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub use channel::{Channel, Listener};

/// Ёмкость реестра (максимальное число атрибутов).
pub const MAX_ATTRS: usize = 1024;

/// Ошибки сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Реестр переполнен (`MAX_ATTRS`).
    RegistryFull,
    /// Объект (OBIS) или атрибут не найден.
    NotFound,
    /// Атрибут недоступен для записи (Static/Dynamic).
    ReadOnly,
    /// Уровень доступа клиента недостаточен.
    AccessDenied,
    /// `class_id` в запросе не совпал с классом объекта.
    UnknownClass { expected: ClassId, got: ClassId },
    /// Ошибка кодера/декодера COSEM PDU.
    Codec(cosempdu::Error),

    // ---------------------------------------------------------------------
    // Транспортный слой (задействуются при включённом канале optical/tcp/ble)
    // ---------------------------------------------------------------------
    /// Нет свободного транспортного слота (пул канала заполнен).
    NoSlot,
    /// Таблица сессий заполнена.
    TooManySessions,
    /// Передан неверный индекс сессии.
    InvalidSession,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RegistryFull => write!(f, "registry full (MAX_ATTRS)"),
            Error::NotFound => write!(f, "object/attribute not found"),
            Error::ReadOnly => write!(f, "attribute is read-only"),
            Error::AccessDenied => write!(f, "access denied"),
            Error::UnknownClass { expected, got } => {
                write!(f, "class mismatch: expected {expected:?}, got {got:?}")
            }
            Error::Codec(e) => write!(f, "{e}"),
            Error::NoSlot => write!(f, "no free transport slot"),
            Error::TooManySessions => write!(f, "too many sessions"),
            Error::InvalidSession => write!(f, "invalid session slot"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<cosempdu::Error> for Error {
    fn from(e: cosempdu::Error) -> Self {
        Error::Codec(e)
    }
}

/// Битовая маска уровней доступа (каждый уровень — свой бит).
///
/// Уровни не пересекаются, поэтому доступ задаётся набором бит. Приложение может
/// определить свои уровни через `AccessMask(1 << n)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessMask(pub u8);

impl AccessMask {
    pub const PUBLIC: Self = AccessMask(1 << 0);
    pub const READER: Self = AccessMask(1 << 1);
    pub const CONFIGURATOR: Self = AccessMask(1 << 2);

    /// Есть ли пересечение с `mask` (т.е. уровень входит в набор).
    pub fn contains(self, mask: AccessMask) -> bool {
        self.0 & mask.0 != 0
    }
}

impl core::ops::BitOr for AccessMask {
    type Output = AccessMask;
    fn bitor(self, rhs: AccessMask) -> AccessMask {
        AccessMask(self.0 | rhs.0)
    }
}

/// Права доступа к атрибуту.
#[derive(Debug, Clone, Copy)]
pub struct Access {
    /// Уровни, которым разрешено чтение (GET).
    pub read: AccessMask,
    /// Уровни, которым разрешена запись (SET; только `Persistent`).
    pub write: AccessMask,
}

/// Ссылка на типизированное значение атрибута + права доступа + вид изменяемости.
pub enum ValueRef<'a> {
    /// Read-only значение (никто не меняет).
    Static(&'a dyn Codec, Access),
    /// Меняется только самим сервером (`update`).
    Dynamic(&'a mut dyn Codec, Access),
    /// Меняется извне через SET; сохраняется в NVM.
    Persistent(&'a mut dyn Codec, Access),
}

/// Бэкенд энергонезависимой памяти (flash/EEPROM) для `Persistent`-атрибутов.
///
/// Крейт `server` не зависит от конкретного железа — реализацию предоставляет
/// приложение.
pub trait Nvm {
    fn load(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), Error>;
    fn save(&mut self, offset: usize, buf: &[u8]) -> Result<(), Error>;
    fn commit(&mut self) -> Result<(), Error>;
}

/// Реестр атрибутов: отсортированный по ключу массив + бинарный поиск.
pub struct Registry<'a> {
    entries: [Option<(AttributeKey, ValueRef<'a>)>; MAX_ATTRS],
    len: usize,
}

impl<'a> Registry<'a> {
    pub fn new() -> Self {
        Registry {
            entries: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Бинарный поиск значения по ключу.
    pub fn get(&self, key: &AttributeKey) -> Option<&ValueRef<'a>> {
        let idx = {
            let occupied = &self.entries[..self.len];
            occupied.binary_search_by(|e| e.as_ref().unwrap().0.cmp(key)).ok()?
        };
        Some(&self.entries[idx].as_ref().unwrap().1)
    }

    /// Бинарный поиск значения по ключу (мутабельно).
    pub fn get_mut(&mut self, key: &AttributeKey) -> Option<&mut ValueRef<'a>> {
        let idx = {
            let occupied = &self.entries[..self.len];
            occupied.binary_search_by(|e| e.as_ref().unwrap().0.cmp(key)).ok()?
        };
        Some(&mut self.entries[idx].as_mut().unwrap().1)
    }

    /// Вставка/обновление. Вставка нового ключа — O(n) сдвиг (редкая операция).
    pub fn insert(&mut self, key: AttributeKey, value: ValueRef<'a>) -> Result<(), Error> {
        let pos = {
            let occupied = &self.entries[..self.len];
            occupied.binary_search_by(|e| e.as_ref().unwrap().0.cmp(&key))
        };
        match pos {
            Ok(i) => {
                self.entries[i].as_mut().unwrap().1 = value;
                Ok(())
            }
            Err(pos) => {
                if self.len >= MAX_ATTRS {
                    return Err(Error::RegistryFull);
                }
                for i in (pos..self.len).rev() {
                    let e = self.entries[i].take();
                    self.entries[i + 1] = e;
                }
                self.entries[pos] = Some((key, value));
                self.len += 1;
                Ok(())
            }
        }
    }
}

impl<'a> Default for Registry<'a> {
    fn default() -> Self {
        Registry::new()
    }
}

/// COSEM-сервер: каталог объектов + реестр атрибутов + предлагаемое
/// согласование возможностей (conformance).
pub struct Server<'a, const N: usize = 3> {
    objects: &'static [&'static dyn InterfaceClass],
    attributes: Registry<'a>,
    /// Conformance, предлагаемый сервером при ассоциации (AARQ).
    proposed_conformance: Conformance,

    #[cfg(feature = "optical")]
    optical_pool: HdlcPool<N>,
    #[cfg(feature = "tcp")]
    tcp_pool: WrapperPool<N>,
    #[cfg(feature = "ble")]
    ble_pool: WrapperPool<N>,

    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    sessions: [Option<Session>; N],
}

impl<'a, const N: usize> Server<'a, N> {
    /// Создать сервер с каталогом COSEM-объектов (для валидации `class_id` + OBIS),
    /// `N` одновременными сессиями и предлагаемым conformance.
    pub fn with_capacity(
        objects: &'static [&'static dyn InterfaceClass],
        conformance: Conformance,
    ) -> Self {
        Server {
            objects,
            attributes: Registry::new(),
            proposed_conformance: conformance,
            #[cfg(feature = "optical")]
            optical_pool: HdlcPool::<N>::new(),
            #[cfg(feature = "tcp")]
            tcp_pool: WrapperPool::<N>::new(0), // собственный wPort — через Server::set_wport
            #[cfg(feature = "ble")]
            ble_pool: WrapperPool::<N>::new(0), // собственный wPort — через Server::set_ble_port
            #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
            sessions: [const { None }; N],
        }
    }

    /// Conformance, предлагаемый сервером (до согласования в AARQ/AARE).
    pub fn proposed_conformance(&self) -> Conformance {
        self.proposed_conformance
    }

    /// Задать собственный wPort сервера для TCP-канала (до приёма соединений).
    #[cfg(feature = "tcp")]
    pub fn set_wport(&mut self, port: u16) {
        self.tcp_pool.set_source_port(port);
    }

    /// Задать собственный wPort сервера для BLE-канала (до приёма соединений).
    #[cfg(feature = "ble")]
    pub fn set_ble_port(&mut self, port: u16) {
        self.ble_pool.set_source_port(port);
    }

    /// Найти объект по OBIS и проверить `class_id`.
    fn find_object(&self, class_id: ClassId, obis: &ObisCode) -> Result<&'static dyn InterfaceClass, Error> {
        let obj = self
            .objects
            .iter()
            .find(|o| o.obis() == *obis)
            .copied()
            .ok_or(Error::NotFound)?;
        if obj.class_id() != class_id {
            return Err(Error::UnknownClass {
                expected: obj.class_id(),
                got: class_id,
            });
        }
        Ok(obj)
    }

    /// Зарегистрировать read-only значение.
    pub fn add_static(&mut self, key: AttributeKey, attr: &'a dyn Codec, access: Access) -> Result<(), Error> {
        self.attributes.insert(key, ValueRef::Static(attr, access))
    }

    /// Зарегистрировать значение, изменяемое только самим сервером.
    pub fn add_dynamic(&mut self, key: AttributeKey, attr: &'a mut dyn Codec, access: Access) -> Result<(), Error> {
        self.attributes.insert(key, ValueRef::Dynamic(attr, access))
    }

    /// Зарегистрировать значение, изменяемое извне через SET (NVM).
    pub fn add_persistent(&mut self, key: AttributeKey, attr: &'a mut dyn Codec, access: Access) -> Result<(), Error> {
        // TODO: NVM — регистрация + восстановление из заводского дефолта.
        self.attributes.insert(key, ValueRef::Persistent(attr, access))
    }

    /// Найти атрибут и вернуть его значение как `&dyn Codec` (после проверки
    /// `class_id` и права чтения).
    pub fn get_codec(
        &self,
        class_id: ClassId,
        key: AttributeKey,
        level: AccessMask,
    ) -> Result<&dyn Codec, Error> {
        self.find_object(class_id, &key.obis)?;
        match self.attributes.get(&key).ok_or(Error::NotFound)? {
            ValueRef::Static(a, access) => {
                if !access.read.contains(level) { return Err(Error::AccessDenied); }
                Ok(*a)
            }
            ValueRef::Dynamic(a, access) | ValueRef::Persistent(a, access) => {
                if !access.read.contains(level) { return Err(Error::AccessDenied); }
                Ok(&**a)
            }
        }
    }

    /// PUT: положить закодированное значение в `buf`, с проверкой права чтения.
    pub fn put(
        &self,
        class_id: ClassId,
        key: AttributeKey,
        level: AccessMask,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<(), Error> {
        self.get_codec(class_id, key, level)?.put(buf)?;
        Ok(())
    }

    /// SET (внешний) поточно: начать приём сегментированного значения, которое
    /// декодируется прямо в атрибут. Возвращает дескриптор для подачи блоков.
    pub fn stream_set<'s>(
        &'s mut self,
        class_id: ClassId,
        key: AttributeKey,
        level: AccessMask,
    ) -> Result<StreamingSet<'s>, Error> {
        self.find_object(class_id, &key.obis)?;
        match self.attributes.get_mut(&key) {
            Some(ValueRef::Persistent(a, access)) => {
                if !access.write.contains(level) { return Err(Error::AccessDenied); }
                let sink = a.stream_sink().ok_or_else(|| {
                    Error::Codec(cosempdu::Error::Message("attribute does not support streaming"))
                })?;
                Ok(StreamingSet { decoder: StreamDecoder::new(sink) })
            }
            Some(ValueRef::Static(..)) | Some(ValueRef::Dynamic(..)) => return Err(Error::ReadOnly),
            None => return Err(Error::NotFound),
        }
    }

    /// Внутреннее обновление `Dynamic`-атрибута (без проверки уровня и class_id).
    pub fn update(&mut self, key: AttributeKey, data: &Data<'_>) -> Result<(), Error> {
        match self.attributes.get_mut(&key) {
            Some(ValueRef::Dynamic(a, _)) => { a.assign(data)?; }
            Some(ValueRef::Static(..)) | Some(ValueRef::Persistent(..)) => return Err(Error::ReadOnly),
            None => return Err(Error::NotFound),
        }
        Ok(())
    }

    /// Число одновременных сессий, которое поддерживает сервер.
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub const fn capacity(&self) -> usize { N }

    /// Доступ к сессии по индексу (для чтения/записи буферов и состояния).
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub fn session(&mut self, idx: usize) -> Option<&mut Session> {
        self.sessions.get_mut(idx).and_then(Option::as_mut)
    }

    /// Вызывается при принятии нового соединения.
    ///
    /// Возвращает индекс слота сессии.
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub fn on_connect(&mut self, media: Media) -> Result<usize, Error> {
        let transport_ref = match media {
            #[cfg(feature = "optical")]
            Media::Optical => {
                self.optical_pool.alloc().ok_or(Error::NoSlot)?;
                TransportRef::Hdlc(HdlcState::new())
            }
            #[cfg(feature = "tcp")]
            Media::Tcp => {
                self.tcp_pool.alloc().ok_or(Error::NoSlot)?;
                TransportRef::Wrapper(WrapperSetting::new(self.tcp_pool.source_port()))
            }
            #[cfg(feature = "ble")]
            Media::Ble => {
                self.ble_pool.alloc().ok_or(Error::NoSlot)?;
                TransportRef::Wrapper(WrapperSetting::new(self.ble_pool.source_port()))
            }
        };

        match self.sessions.iter().position(|s| s.is_none()) {
            Some(i) => {
                self.sessions[i] = Some(Session::new(media, transport_ref));
                Ok(i)
            }
            None => {
                // Сессий нет — откатываем транспортный слот.
                self.release(media);
                Err(Error::TooManySessions)
            }
        }
    }

    /// Вызывается при закрытии соединения.
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub fn on_disconnect(&mut self, session_idx: usize) {
        if let Some(session) = self.sessions.get_mut(session_idx).and_then(Option::take) {
            self.release(session.media());
        }
    }

    /// Вызывается при поступлении байтов в соединение.
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub fn on_data(&mut self, session_idx: usize, data: &[u8]) -> Result<(), Error> {
        let session = self
            .sessions
            .get_mut(session_idx)
            .and_then(Option::as_mut)
            .ok_or(Error::InvalidSession)?;

        let needed = session.rx_len() + data.len();
        if !session.push_rx(data) {
            return Err(Error::Codec(cosempdu::Error::InputTooLarge {
                len: needed,
                max: RX_BUF,
            }));
        }

        // TODO: разбор кадра происходит в `associate` (Wrapper) / HDLC-обработке
        // (по `TransportRef::Hdlc`); здесь только накопление байт.
        Ok(())
    }

    /// Транспортный слой: валидация Wrapper-заголовка (WPDU адресован нашему
    /// wPort) и сохранение согласованных настроек соединения в сессию.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    pub fn validate_wrapper(
        &mut self,
        session_idx: usize,
        received: WrapperSetting,
    ) -> Result<(), Error> {
        let session = self.session(session_idx).ok_or(Error::InvalidSession)?;

        // Собственный wPort сервера уже сохранён в TransportRef при on_connect.
        let server_port = match session.transport_ref() {
            TransportRef::Wrapper(s) => s.source_port(),
            #[cfg(feature = "optical")]
            TransportRef::Hdlc(_) => {
                return Err(Error::Codec(cosempdu::Error::Message(
                    "wrapper validation requires tcp/ble channel",
                )))
            }
        };

        // Валидация: клиент должен адресовать WPDU нашему wPort.
        if received.destination_port() != server_port {
            return Err(Error::Codec(cosempdu::Error::Message(
                "wrong destination wPort",
            )));
        }

        // Сохранить настройки соединения (взгляд сервера: наш порт → порт клиента).
        let mut setting = WrapperSetting::new(server_port);
        setting.set_destination_port(received.source_port());
        session.set_transport_ref(TransportRef::Wrapper(setting));
        Ok(())
    }

    /// DLMS-слой: принять ассоциацию — AARQ из session.rx → AARE в session.tx.
    ///
    /// Вызывается после успешной [`Server::validate_wrapper`].
    #[cfg(any(feature = "tcp", feature = "ble"))]
    pub fn accept_association(
        &mut self,
        session_idx: usize,
        received: WrapperSetting,
    ) -> Result<(), Error> {
        let conf = self.proposed_conformance();
        let session = self.session(session_idx).ok_or(Error::InvalidSession)?;

        // Настройки ответа (взгляд сервера) сохранены в validate_wrapper.
        let setting = match session.transport_ref() {
            TransportRef::Wrapper(s) => s,
            #[cfg(feature = "optical")]
            TransportRef::Hdlc(_) => {
                return Err(Error::Codec(cosempdu::Error::Message(
                    "accept requires Wrapper channel (tcp/ble)",
                )))
            }
        };

        // 1. Извлечь AARQ (payload после 8-байтного заголовка) и собрать AARE.
        let (aare_apdu, aare_len) = {
            let apdu = &session.rx()
                [TRANSPORT_OVERHEAD..TRANSPORT_OVERHEAD + received.apdu_len() as usize];
            aarq_to_aare(apdu, conf)?
        };

        // 2. Обернуть AARE в WPDU и записать в session.tx.
        let n = {
            let mut tx = session.tx_buffer();
            setting.put(&aare_apdu[..aare_len], &mut tx).map_err(Error::Codec)?
        };
        session.set_tx_len(n);
        Ok(())
    }

    /// Обслужить одно соединение: read → associate → write (embedded/один клиент).
    #[cfg(any(feature = "tcp", feature = "ble"))]
    pub async fn serve<C: Channel<Frame = WrapperSetting>>(
        &mut self,
        media: Media,
        mut channel: C,
    ) -> Result<(), Error> {
        let idx = self.on_connect(media)?;
        let result = self.serve_loop(idx, &mut channel).await;
        // Всегда освобождаем сессию (сброс в Idle): и при успехе, и при таймауте/ошибке.
        self.on_disconnect(idx);
        result
    }

    /// Обработать один кадр соединения: read → validate → accept → write.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    pub async fn handle_frame<C: Channel<Frame = WrapperSetting>>(
        &mut self,
        idx: usize,
        channel: &mut C,
    ) -> Result<(), Error> {
        // Читаем WPDU прямо в session.rx; канал возвращает метаданные кадра.
        let setting = {
            let session = self.session(idx).ok_or(Error::InvalidSession)?;
            let setting = channel.read(session.rx_mut()).await.map_err(Error::Codec)?;
            session.set_rx_len(TRANSPORT_OVERHEAD + setting.apdu_len() as usize);
            setting
        };
        // Валидация Wrapper и приём AARQ → AARE (в session.tx).
        self.validate_wrapper(idx, setting)?;
        self.accept_association(idx, setting)?;
        // Пишем ответ прямо из session.tx.
        {
            let session = self.session(idx).ok_or(Error::InvalidSession)?;
            channel.write(session.tx()).await.map_err(Error::Codec)?;
            session.clear_rx();
        }
        Ok(())
    }

    #[cfg(any(feature = "tcp", feature = "ble"))]
    async fn serve_loop<C: Channel<Frame = WrapperSetting>>(
        &mut self,
        idx: usize,
        channel: &mut C,
    ) -> Result<(), Error> {
        loop {
            self.handle_frame(idx, channel).await?;
        }
    }

    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    fn release(&mut self, media: Media) {
        match media {
            #[cfg(feature = "optical")]
            Media::Optical => self.optical_pool.free(),
            #[cfg(feature = "tcp")]
            Media::Tcp => self.tcp_pool.free(),
            #[cfg(feature = "ble")]
            Media::Ble => self.ble_pool.free(),
        }
    }
}

impl<'a> Server<'a, 3> {
    /// Создать сервер с дефолтным числом сессий (3) и предлагаемым conformance.
    pub fn new(
        objects: &'static [&'static dyn InterfaceClass],
        conformance: Conformance,
    ) -> Self {
        Self::with_capacity(objects, conformance)
    }
}

/// AARQ APDU → AARE APDU (байты). Транспортно-независимо.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn aarq_to_aare(apdu: &[u8], server_conf: Conformance) -> Result<([u8; 256], usize), Error> {
    let acse = ACSEApdu::get(&mut Reader::new(apdu)).map_err(Error::Codec)?;
    let aarq = match acse {
        ACSEApdu::Aarq(a) => a,
        _ => return Err(Error::Codec(cosempdu::Error::Message("expected AARQ"))),
    };
    let ui = aarq
        .user_information
        .ok_or_else(|| Error::Codec(cosempdu::Error::Message("AARQ without user-information")))?;
    let req = InitiateRequest::get(&mut Reader::new(ui)).map_err(Error::Codec)?;

    // Согласование: пересечение возможностей клиента и сервера.
    let (c, s) = (req.proposed_conformance.0, server_conf.0);
    let negotiated = Conformance([c[0] & s[0], c[1] & s[1], c[2] & s[2]]);

    let resp = InitiateResponse {
        negotiated_quality_of_service: None,
        negotiated_dlms_version_number: 6,
        negotiated_conformance: negotiated,
        server_max_receive_pdu_size: MAX_APDU as u16,
        vaa_name: ObjectName(0x0007),
    };
    let mut ir = [0u8; 64];
    let n = resp.put(&mut ByteBuffer::new(&mut ir)).map_err(Error::Codec)?;

    let aare = AAREapdu {
        protocol_version: None,
        application_context_name: aarq.application_context_name,
        result: 0,
        result_source_diagnostic: 0,
        responding_ap_title: None,
        responding_ae_qualifier: None,
        responding_ap_invocation_id: None,
        responding_ae_invocation_id: None,
        responder_acse_requirements: None,
        mechanism_name: None,
        responding_authentication_value: None,
        implementation_information: None,
        user_information: Some(&ir[..n]),
    };
    let mut out = [0u8; 256];
    let m = aare.put(&mut ByteBuffer::new(&mut out)).map_err(Error::Codec)?;
    Ok((out, m))
}

/// Обработка `Get-Request` → `Get-Response` (мост APDU → Server).
///
/// Только `GetRequest::Normal` без `access_selection`.
// TODO: поддержка `Next` / `WithList` и `access_selection`.
// TODO: маппинг `Error` → `GetDataResultWrite::DataAccessError(...)` (пока — `Err`).
pub fn handle_get<'a, const N: usize>(
    server: &Server<'a, N>,
    req: &GetRequest<'_>,
    buf: &mut ByteBuffer<'_>,
) -> Result<(), Error> {
    match req {
        GetRequest::Normal {
            invoke,
            descriptor,
            access_selection: None,
        } => {
            let class_id = ClassId::from_u16(descriptor.class_id).ok_or(Error::NotFound)?;
            let obis = ObisCode::from_bytes(descriptor.instance_id);
            let key = AttributeKey::new(obis, descriptor.attribute_id as u8);
            let codec = server.get_codec(class_id, key, AccessMask::PUBLIC)?;
            GetResponse::put_normal(*invoke, GetDataResultWrite::Data(codec), buf)?;
            Ok(())
        }
        _ => Err(Error::NotFound),
    }
}

/// Дескриптор потокового SET: держит декодер поверх приёмника атрибута, пока
/// принимаются блоки значения.
pub struct StreamingSet<'s> {
    decoder: StreamDecoder<'s, dyn StreamSink + 's>,
}

impl<'s> StreamingSet<'s> {
    /// Подать очередной кусок A-XDR-байт значения.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.decoder.push(bytes)?;
        Ok(())
    }

    /// Завершить поток; ошибка, если значение неполно.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.decoder.finish()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlms1::common_data_types::{DateTime, DoubleLongUnsigned, OctetString};
    use dlms1::ic::{Clock, DataObject, Register, RegisterActivation, RegisterAssignmentValue, ScalUnit};
    use cosempdu::apdu::{CosemAttributeDescriptor, GetDataResult, InvokeIdAndPriority};
    use cosempdu::apdu_sn::Conformance;
    use cosempdu::buffer::Reader;

    const CONF: Conformance = Conformance([0x00, 0x7E, 0x1F]);

    static SERIAL_OBJ: DataObject = DataObject::new(ObisCode::new(0, 0, 96, 1, 0, 255));
    static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
    static CLOCK_OBJ: Clock = Clock::new(ObisCode::CLOCK);
    static RA_OBJ: RegisterActivation = RegisterActivation::new(ObisCode::new(0, 0, 96, 1, 1, 255));
    static OBJECTS: &[&dyn InterfaceClass] = &[&SERIAL_OBJ, &REG_OBJ, &CLOCK_OBJ, &RA_OBJ];

    fn reg_access() -> Access {
        Access {
            read: AccessMask::PUBLIC | AccessMask::READER | AccessMask::CONFIGURATOR,
            write: AccessMask::CONFIGURATOR,
        }
    }

    #[test]
    fn server_handles_get_request_normal() {
        // 1) сервер + зарегистрированный атрибут (Register attr 2 = value)
        let mut server = Server::new(OBJECTS, CONF);
        let reg = DoubleLongUnsigned(42);
        server.add_static(REG_OBJ.attr_key(2).unwrap(), &reg, reg_access()).unwrap();

        // 2) закодировать GetRequest::Normal в "буфер приёма"
        let mut rx = [0u8; 128];
        let rx_n = {
            let mut b = ByteBuffer::new(&mut rx);
            GetRequest::put_normal(
                InvokeIdAndPriority::from_bits(1, true, false),
                CosemAttributeDescriptor {
                    class_id: ClassId::Register.as_u16(),
                    instance_id: REG_OBJ.obis().bytes,
                    attribute_id: 2,
                },
                None,
                &mut b,
            )
            .unwrap()
        };

        // 3) декодировать запрос
        let req = {
            let mut r = Reader::new(&rx[..rx_n]);
            GetRequest::get(&mut r).unwrap()
        };

        // 4) обработать и записать GetResponse в "буфер передачи"
        let mut tx = [0u8; 128];
        let tx_n = {
            let mut b = ByteBuffer::new(&mut tx);
            handle_get(&server, &req, &mut b).unwrap();
            b.pos()
        };

        // 5) декодировать ответ
        let resp = {
            let mut r = Reader::new(&tx[..tx_n]);
            GetResponse::get(&mut r).unwrap()
        };

        // 6) сверить
        match resp {
            GetResponse::Normal { invoke, result: GetDataResult::Data(r) } => {
                assert_eq!(invoke.invoke_id(), 1);
                let mut eb = [0u8; 16];
                let en = {
                    let mut b = ByteBuffer::new(&mut eb);
                    reg.put(&mut b).unwrap()
                };
                assert_eq!(r.as_bytes(), &eb[..en]);
            }
            _ => panic!("expected GetResponse::Normal with data"),
        }
    }

    /// Тестовый хелпер: применить `Data` к атрибуту через потоковый SET.
    fn set_data(
        server: &mut Server<'_>,
        class_id: ClassId,
        key: AttributeKey,
        level: AccessMask,
        data: &Data<'_>,
    ) -> Result<(), Error> {
        let mut backing = [0u8; 128];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            data.put(&mut b).map_err(Error::from)?
        };
        let mut s = server.stream_set(class_id, key, level)?;
        s.push(&backing[..n])?;
        s.finish()
    }

    #[test]
    fn registry_sorted_insert_and_search() {
        static A: DoubleLongUnsigned = DoubleLongUnsigned(1);
        let acc = Access { read: AccessMask::PUBLIC, write: AccessMask::CONFIGURATOR };
        let mut r = Registry::new();
        let k1 = AttributeKey::new(ObisCode::new(1, 0, 0, 0, 0, 0), 1);
        let k2 = AttributeKey::new(ObisCode::new(2, 0, 0, 0, 0, 0), 1);
        let k3 = AttributeKey::new(ObisCode::new(3, 0, 0, 0, 0, 0), 1);
        r.insert(k1, ValueRef::Static(&A, acc)).unwrap();
        r.insert(k3, ValueRef::Static(&A, acc)).unwrap();
        r.insert(k2, ValueRef::Static(&A, acc)).unwrap();
        assert_eq!(r.len(), 3);
        assert!(r.get(&k1).is_some());
        assert!(r.get(&k2).is_some());
        assert!(r.get(&k3).is_some());
        assert!(r.get(&AttributeKey::new(ObisCode::new(9, 9, 9, 9, 9, 9), 1)).is_none());
    }

    #[test]
    fn server_get_set_persistent() {
        let mut server = Server::new(OBJECTS, CONF);

        static SN: DoubleLongUnsigned = DoubleLongUnsigned(123456);
        let serial = SERIAL_OBJ.value();
        server.add_static(serial, &SN, Access { read: AccessMask::PUBLIC, write: AccessMask::CONFIGURATOR }).unwrap();

        let mut register = DoubleLongUnsigned(230000);
        let rw = REG_OBJ.value();
        server.add_persistent(rw, &mut register, reg_access()).unwrap();

        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);
        server.put(ClassId::Register, REG_OBJ.value(), AccessMask::READER, &mut buf).unwrap();
        assert_eq!(buf.extract(), &[0x06, 0x00, 0x03, 0x82, 0x70]);

        set_data(&mut server, ClassId::Register, REG_OBJ.value(), AccessMask::CONFIGURATOR, &Data::DoubleLongUnsigned(1)).unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            server.put(ClassId::Register, REG_OBJ.value(), AccessMask::PUBLIC, &mut buf).unwrap();
            assert_eq!(buf.extract(), &[0x06, 0x00, 0x00, 0x00, 0x01]);
        }

        assert_eq!(server.put(ClassId::Register, REG_OBJ.value(), AccessMask(1 << 3), &mut buf), Err(Error::AccessDenied));
        assert_eq!(set_data(&mut server, ClassId::Register, REG_OBJ.value(), AccessMask::PUBLIC, &Data::DoubleLongUnsigned(2)), Err(Error::AccessDenied));
        assert!(set_data(&mut server, ClassId::Register, REG_OBJ.value(), AccessMask::CONFIGURATOR, &Data::Unsigned(200)).is_err());
        assert_eq!(set_data(&mut server, ClassId::Data, SERIAL_OBJ.value(), AccessMask::CONFIGURATOR, &Data::Unsigned(0)), Err(Error::ReadOnly));

        let missing = ObisCode::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        assert_eq!(server.put(ClassId::Register, AttributeKey::new(missing, 2), AccessMask::PUBLIC, &mut buf), Err(Error::NotFound));
        assert_eq!(set_data(&mut server, ClassId::Register, AttributeKey::new(missing, 2), AccessMask::PUBLIC, &Data::NullData), Err(Error::NotFound));
    }

    #[test]
    fn server_dynamic_update() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut clock_time = DateTime([0; 12]);
        server.add_dynamic(CLOCK_OBJ.time(), &mut clock_time, reg_access()).unwrap();

        let t: [u8; 12] = [0x07, 0xE8, 0x0A, 0x09, 0x00, 0x0F, 0x2A, 0x00, 0x00, 0x00, 0x00, 0xFF];
        server.update(CLOCK_OBJ.time(), &Data::DateTime(t)).unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            server.put(ClassId::Clock, CLOCK_OBJ.time(), AccessMask::PUBLIC, &mut buf).unwrap();
            assert_eq!(buf.extract(), &[0x19, 0x07, 0xE8, 0x0A, 0x09, 0x00, 0x0F, 0x2A, 0x00, 0x00, 0x00, 0x00, 0xFF]);
        }

        assert_eq!(set_data(&mut server, ClassId::Clock, CLOCK_OBJ.time(), AccessMask::CONFIGURATOR, &Data::DateTime(t)), Err(Error::ReadOnly));

        let mut p = ScalUnit { scaler: 0, unit: 255 };
        let pkey = REG_OBJ.scaler_unit();
        server.add_persistent(pkey, &mut p, reg_access()).unwrap();
        assert_eq!(server.update(REG_OBJ.scaler_unit(), &Data::Structure(&[Data::Integer(0), Data::Enum(255)])), Err(Error::ReadOnly));
    }

    #[test]
    fn server_stream_set_scalar() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut register = DoubleLongUnsigned(0);
        let key = REG_OBJ.value();
        server.add_persistent(key, &mut register, reg_access()).unwrap();

        // Encode DoubleLongUnsigned(42) = [tag 6, 0x00, 0x00, 0x00, 0x2A].
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            Data::DoubleLongUnsigned(42).put(&mut buf).unwrap()
        };

        {
            let mut s = server.stream_set(ClassId::Register, key, AccessMask::CONFIGURATOR).unwrap();
            let mid = n / 2;
            s.push(&backing[..mid]).unwrap();
            s.push(&backing[mid..n]).unwrap();
            s.finish().unwrap();
        }

        let mut out = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut out);
        server.put(ClassId::Register, key, AccessMask::PUBLIC, &mut buf).unwrap();
        assert_eq!(buf.extract(), &[0x06, 0x00, 0x00, 0x00, 0x2A]);
    }

    #[test]
    fn server_stream_set_composite() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut scal = ScalUnit { scaler: 0, unit: 255 };
        let key = REG_OBJ.scaler_unit();
        server.add_persistent(key, &mut scal, reg_access()).unwrap();

        // Encode Structure(Integer(3), Enum(1)).
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            Data::Structure(&[Data::Integer(3), Data::Enum(1)]).put(&mut buf).unwrap()
        };

        {
            let mut s = server.stream_set(ClassId::Register, key, AccessMask::CONFIGURATOR).unwrap();
            s.push(&backing[..n]).unwrap();
            s.finish().unwrap();
        }

        let mut out = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut out);
        server.put(ClassId::Register, key, AccessMask::PUBLIC, &mut buf).unwrap();
        assert_eq!(buf.extract(), &[0x02, 0x02, 0x0F, 0x03, 0x16, 0x01]);
    }

    #[test]
    fn server_stream_set_blob() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut value = OctetString::<60> { buf: [0; 60], len: 0 };
        let key = REG_OBJ.value();
        server.add_persistent(key, &mut value, reg_access()).unwrap();

        // ~60-байтный octet-string, детерминированный паттерн (без heap).
        let content: [u8; 60] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
        let mut backing = [0u8; 128];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            Data::OctetString(&content).put(&mut b).unwrap()
        };

        {
            let mut s = server.stream_set(ClassId::Register, key, AccessMask::CONFIGURATOR).unwrap();
            for chunk in backing[..n].chunks(20) {
                s.push(chunk).unwrap();
            }
            s.finish().unwrap();
        }

        let mut out = [0u8; 128];
        let mut buf = ByteBuffer::new(&mut out);
        server.put(ClassId::Register, key, AccessMask::PUBLIC, &mut buf).unwrap();
        assert_eq!(buf.extract(), &backing[..n]);
    }

    #[test]
    fn server_validate_structure() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut scal = ScalUnit { scaler: 3, unit: 1 };
        let key = REG_OBJ.scaler_unit();
        server.add_persistent(key, &mut scal, reg_access()).unwrap();

        set_data(&mut server, ClassId::Register, REG_OBJ.scaler_unit(), AccessMask::CONFIGURATOR, &Data::Structure(&[Data::Integer(7), Data::Enum(2)])).unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            server.put(ClassId::Register, REG_OBJ.scaler_unit(), AccessMask::PUBLIC, &mut buf).unwrap();
            assert_eq!(buf.extract(), &[0x02, 0x02, 0x0F, 0x07, 0x16, 0x02]);
        }

        assert!(set_data(
            &mut server,
            ClassId::Register,
            REG_OBJ.scaler_unit(),
            AccessMask::CONFIGURATOR,
            &Data::Structure(&[Data::Unsigned(1), Data::Unsigned(2)])
        )
        .is_err());
    }

    #[test]
    fn server_validates_class_id() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut register = DoubleLongUnsigned(0);
        let key = REG_OBJ.value();
        server.add_persistent(key, &mut register, reg_access()).unwrap();

        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);

        server.put(ClassId::Register, REG_OBJ.value(), AccessMask::PUBLIC, &mut buf).unwrap();

        assert!(matches!(
            server.put(ClassId::Clock, REG_OBJ.value(), AccessMask::PUBLIC, &mut buf),
            Err(Error::UnknownClass { .. })
        ));

        let unknown = ObisCode::new(9, 9, 9, 9, 9, 9);
        assert_eq!(server.put(ClassId::Register, AttributeKey::new(unknown, 2), AccessMask::PUBLIC, &mut buf), Err(Error::NotFound));
    }

    #[test]
    fn server_register_activation_register_assignment() {
        // 1. Полностью настраиваем сервер.
        let mut server = Server::new(OBJECTS, CONF);
        let key = RA_OBJ.register_assignment();
        let mut value = RegisterAssignmentValue::<2>::default();
        server.add_persistent(key, &mut value, reg_access()).unwrap();

        // 2. Кодируем array из 2 object_definition.
        let ln0 = ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL;   // 1.0.1.8.0.255
        let ln1 = ObisCode::ACTIVE_ENERGY_EXPORT_TOTAL;   // 1.0.2.8.0.255
        let f0 = [Data::LongUnsigned(ClassId::Register.as_u16()), Data::OctetString(&ln0.bytes)];
        let f1 = [Data::LongUnsigned(ClassId::ExtendedRegister.as_u16()), Data::OctetString(&ln1.bytes)];
        let items = [Data::Structure(&f0), Data::Structure(&f1)];
        let mut backing = [0u8; 128];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            Data::Array(&items).put(&mut b).unwrap()
        };

        // 3. Потоковый приём за 3 прохода через сервер.
        {
            let mut s = server.stream_set(ClassId::RegisterActivation, key, AccessMask::CONFIGURATOR).unwrap();
            let a = n / 3;
            let b = 2 * a;
            s.push(&backing[..a]).unwrap();
            s.push(&backing[a..b]).unwrap();
            s.push(&backing[b..n]).unwrap();
            s.finish().unwrap();
        }

        // 4. Сверяем выдачу.
        let mut out = [0u8; 128];
        let mut buf = ByteBuffer::new(&mut out);
        server.put(ClassId::RegisterActivation, key, AccessMask::PUBLIC, &mut buf).unwrap();
        assert_eq!(buf.extract(), &[
            0x01, 0x02,                                                             // array {2}
            0x02, 0x02, 0x12, 0x00, 0x03, 0x09, 0x06, 0x01, 0x00, 0x01, 0x08, 0x00, 0xFF, // {Register, 1.0.1.8.0.255}
            0x02, 0x02, 0x12, 0x00, 0x04, 0x09, 0x06, 0x01, 0x00, 0x02, 0x08, 0x00, 0xFF, // {ExtendedRegister, 1.0.2.8.0.255}
        ]);
    }

    #[test]
    fn memory_sizes() {
        use core::mem::size_of;
        let entry = size_of::<Option<(AttributeKey, ValueRef<'static>)>>();
        let registry = size_of::<Registry<'static>>();

        println!("AccessMask                  = {} B", size_of::<AccessMask>());
        println!("Access                      = {} B", size_of::<Access>());
        println!("AttributeKey                = {} B", size_of::<AttributeKey>());
        println!("ValueRef<'static>           = {} B", size_of::<ValueRef<'static>>());
        println!("entry Option<(key, ValueRef)> = {} B", entry);
        println!("Registry<'static>           = {} B ({} slots)", registry, MAX_ATTRS);
        println!("Server<'static, 3>          = {} B", size_of::<Server<'static>>());
        println!("registry per 1000 attrs     = {} B ~ {} KB", entry * 1000, entry * 1000 / 1024);
    }
}

#[cfg(all(test, feature = "optical"))]
mod transport_tests {
    use crate::{Error, Media, Server, RX_BUF};
    use cosempdu::apdu_sn::Conformance;
    use dlms1::ic::InterfaceClass;

    const CONF: Conformance = Conformance([0x00, 0x7E, 0x1F]);

    static NO_OBJECTS: &[&dyn InterfaceClass] = &[];

    #[test]
    fn connect_disconnect_and_slot_reuse() {
        let mut server: Server = Server::new(NO_OBJECTS, CONF);

        let i0 = server.on_connect(Media::Optical).unwrap();
        assert_eq!(i0, 0);
        let i1 = server.on_connect(Media::Optical).unwrap();
        assert_eq!(i1, 1);
        let i2 = server.on_connect(Media::Optical).unwrap();
        assert_eq!(i2, 2);

        // Лимит сессий и пула оптики (N = 3) исчерпан.
        assert!(matches!(server.on_connect(Media::Optical), Err(Error::NoSlot)));

        // Освобождение сессии возвращает транспортный слот.
        server.on_disconnect(i0);
        let i3 = server.on_connect(Media::Optical).unwrap();
        assert_eq!(i3, 0);
    }

    #[test]
    fn data_accumulates_and_overflow() {
        let mut server: Server = Server::new(NO_OBJECTS, CONF);
        let i = server.on_connect(Media::Optical).unwrap();

        server.on_data(i, &[1, 2, 3]).unwrap();
        assert_eq!(server.session(i).unwrap().rx(), &[1, 2, 3]);

        // Переполнение rx-буфера.
        let big = [0u8; RX_BUF + 1];
        assert!(matches!(
            server.on_data(i, &big),
            Err(Error::Codec(cosempdu::Error::InputTooLarge { .. }))
        ));
    }

    #[test]
    fn invalid_session_is_error() {
        let mut server: Server = Server::new(NO_OBJECTS, CONF);
        assert!(matches!(server.on_data(0, &[1]), Err(Error::InvalidSession)));
        server.on_disconnect(0); // не паникует
    }
}

#[cfg(all(test, any(feature = "tcp", feature = "ble")))]
mod wrapper_tests {
    use crate::{Wrapper, WrapperSetting};
    use cosempdu::buffer::{ByteBuffer, Reader};

    #[test]
    fn wrapper_put_get_roundtrip() {
        let mut setting = WrapperSetting::new(0);
        setting.set_destination_port(0x1234);

        let apdu = [0x0F, 0x01, 0x02, 0x03];
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            setting.put(&apdu, &mut buf).unwrap()
        };

        let mut reader = Reader::new(&backing[..n]);
        let decoded = WrapperSetting::get(&mut reader).unwrap();
        assert_eq!(decoded.apdu_len() as usize, apdu.len());
        assert_eq!(decoded.destination_port(), 0x1234);
        assert_eq!(decoded.source_port(), 0);
        assert_eq!(reader.read(decoded.apdu_len() as usize).unwrap(), &apdu[..]);
    }
}



