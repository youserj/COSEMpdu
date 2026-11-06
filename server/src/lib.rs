//! Минимальный DLMS/COSEM сервер (реестр атрибутов + каталог объектов).
//!
//! Атрибуты хранятся **по отдельности** — типизированные значения [`Attribute`],
//! права доступа [`Access`] и вид изменяемости ([`ValueRef`]). Поэтому каждый
//! атрибут размещается в памяти независимо (`static` → ROM, `static mut` → RAM).
//! Каталог COSEM-объектов ([`InterfaceClass`]) хранится в сервере как
//! `static`-срез и используется для валидации входящих запросов
//! (`class_id` + OBIS). Куча не используется (no-heap, готово к `no_std`).
//!
//! Соединения обслуживаются [`Session`] — значением с буферами `rx`/`tx`, которое
//! принадлежит вызывающему (задаче соединения или [`Server::serve`]), а не
//! серверу. Поэтому I/O канала не требует `&mut Server`: [`Server::on_connect`]
//! возвращает `Session`, а [`Server::process_request`] обрабатывает уже
//! прочитанный WPDU из `session.rx`.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate std;

use core::fmt;

use cosempdu::apdu::{
    CosemAttributeDescriptor, DataAccessResult, GetDataResultWrite, GetResponse,
    InvokeIdAndPriority,
};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::apdu::{
    ExceptionResponse, GetRequest, GetRequestNormal, ImplicitTagged, ServiceError_, SetRequest,
    SetRequestNormal, SetResponse, StateError,
};
use cosempdu::apdu::Conformance;
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::{Codec, Data};
use cosempdu::stream::{StreamDecoder, StreamSink};
use dlms1::ic::{AttributeKey, ClassId, InterfaceClass};
use dlms1::obis::ObisCode;

#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::acse::{
    AAREapdu, AARQapdu, ACSEApdu, AcseServiceUser, ApplicationContextName, AssociateSourceDiagnostic,
    AssociationResult, BerTagged, RLREapdu, ReleaseResponseReason,
};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::apdu::{
    confirmed_service_error_tag, ConfirmedServiceError, DLMS_VERSION_NUMBER, Initiate,
    InitiateRequest, InitiateResponse, SnServiceError
};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::buffer::Reader;
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::x680::{Class, Tag};

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
pub use transport::{Wrapper, WrapperPool, WRAPPER_VERSION};

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
    /// Ошибка доступа к данным (DLMS `Data-Access-Result`).
    DataAccessResult(DataAccessResult),
    /// Ошибка кодера/декодера COSEM PDU.
    Codec(cosempdu::Error),

    // ---------------------------------------------------------------------
    // Транспортный слой (задействуются при включённом канале optical/tcp/ble)
    // ---------------------------------------------------------------------
    /// Нет свободного транспортного слота (пул канала заполнен).
    NoSlot,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RegistryFull => write!(f, "registry full (MAX_ATTRS)"),
            Error::NotFound => write!(f, "object/attribute not found"),
            Error::ReadOnly => write!(f, "attribute is read-only"),
            Error::AccessDenied => write!(f, "access denied"),
            Error::DataAccessResult(r) => write!(f, "data access result: {r:?}"),
            Error::Codec(e) => write!(f, "{e}"),
            Error::NoSlot => write!(f, "no free transport slot"),
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

impl From<cosempdu::buffer::Error> for Error {
    fn from(e: cosempdu::buffer::Error) -> Self {
        Error::Codec(e.into())
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

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Бинарный поиск значения по ключу.
    pub fn get(&self, key: &AttributeKey) -> Option<&ValueRef<'a>> {
        let idx = {
            let occupied = &self.entries[..self.len];
            occupied
                .binary_search_by(|e| e.as_ref().unwrap().0.cmp(key))
                .ok()?
        };
        Some(&self.entries[idx].as_ref().unwrap().1)
    }

    /// Бинарный поиск значения по ключу (мутабельно).
    pub fn get_mut(&mut self, key: &AttributeKey) -> Option<&mut ValueRef<'a>> {
        let idx = {
            let occupied = &self.entries[..self.len];
            occupied
                .binary_search_by(|e| e.as_ref().unwrap().0.cmp(key))
                .ok()?
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
    fn find_object(
        &self,
        class_id: ClassId,
        obis: &ObisCode,
    ) -> Result<&'static dyn InterfaceClass, Error> {
        let obj = self
            .objects
            .iter()
            .find(|o| o.obis() == *obis)
            .copied()
            .ok_or(Error::DataAccessResult(DataAccessResult::ObjectUnavailable))?;
        if obj.class_id() != class_id {
            return Err(Error::DataAccessResult(
                DataAccessResult::ObjectClassInconsistent,
            ));
        }
        Ok(obj)
    }

    /// Зарегистрировать read-only значение.
    pub fn add_static(
        &mut self,
        key: AttributeKey,
        attr: &'a dyn Codec,
        access: Access,
    ) -> Result<(), Error> {
        self.attributes.insert(key, ValueRef::Static(attr, access))
    }

    /// Зарегистрировать значение, изменяемое только самим сервером.
    pub fn add_dynamic(
        &mut self,
        key: AttributeKey,
        attr: &'a mut dyn Codec,
        access: Access,
    ) -> Result<(), Error> {
        self.attributes.insert(key, ValueRef::Dynamic(attr, access))
    }

    /// Зарегистрировать значение, изменяемое извне через SET (NVM).
    pub fn add_persistent(
        &mut self,
        key: AttributeKey,
        attr: &'a mut dyn Codec,
        access: Access,
    ) -> Result<(), Error> {
        // TODO: NVM — регистрация + восстановление из заводского дефолта.
        self.attributes
            .insert(key, ValueRef::Persistent(attr, access))
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
                if !access.read.contains(level) {
                    return Err(Error::AccessDenied);
                }
                Ok(*a)
            }
            ValueRef::Dynamic(a, access) | ValueRef::Persistent(a, access) => {
                if !access.read.contains(level) {
                    return Err(Error::AccessDenied);
                }
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

    /// Обработать `Get-Request` (только `Normal` без `access_selection`) и
    /// записать `Get-Response` в `buf`.
    ///
    /// `invoke` + `descriptor` — уже декодированные owned-поля (`Copy`), чтобы
    /// вызывающий код не держал borrow на буфер приёма. Возвращает число
    /// записанных байт. Ошибка доступа к данным уходит в `Get-Response` как
    /// `DataAccessError`, а не прерывает обработку.
    // TODO: поддержка `Next` / `WithList` и `access_selection`.
    // TODO: уровень доступа — из ассоциации, а не жёсткий `AccessMask::PUBLIC`.
    pub fn handle_get(
        &self,
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize, Error> {
        // Получить значение; Data-Access-Result уходит в Get-Response (DataAccessError).
        let result = match self.lookup_codec(descriptor) {
            Ok(codec) => GetDataResultWrite::Data(codec),
            Err(Error::DataAccessResult(code)) => GetDataResultWrite::DataAccessError(code),
            Err(e) => return Err(e),
        };

        let start = buf.pos();
        GetResponse::put_normal(invoke, result, buf)?;
        Ok(buf.pos() - start)
    }

    /// Разобрать дескриптор (class_id + OBIS + attribute_id) и найти значение.
    fn lookup_codec(&self, descriptor: CosemAttributeDescriptor) -> Result<&dyn Codec, Error> {
        let class_id = ClassId::from_u16(descriptor.class_id).ok_or(Error::DataAccessResult(
            DataAccessResult::ObjectClassInconsistent,
        ))?;
        let obis = ObisCode::from_bytes(descriptor.instance_id);
        let key = AttributeKey::new(obis, descriptor.attribute_id as u8);
        self.get_codec(class_id, key, AccessMask::PUBLIC)
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
                if !access.write.contains(level) {
                    return Err(Error::DataAccessResult(
                        DataAccessResult::ScopeOfAccessViolated,
                    ));
                }
                let sink = a
                    .stream_sink()
                    .ok_or_else(|| Error::DataAccessResult(DataAccessResult::HardwareFault))?;
                Ok(StreamingSet {
                    decoder: StreamDecoder::new(sink),
                })
            }
            Some(ValueRef::Static(..)) | Some(ValueRef::Dynamic(..)) => {
                return Err(Error::DataAccessResult(DataAccessResult::ReadWriteDenied))
            }
            None => return Err(Error::DataAccessResult(DataAccessResult::ObjectUndefined)),
        }
    }

    /// Внутреннее обновление `Dynamic`-атрибута (без проверки уровня и class_id).
    pub fn update(&mut self, key: AttributeKey, data: &Data<'_>) -> Result<(), Error> {
        match self.attributes.get_mut(&key) {
            Some(ValueRef::Dynamic(a, _)) => {
                a.assign(data)?;
            }
            Some(ValueRef::Static(..)) | Some(ValueRef::Persistent(..)) => {
                return Err(Error::ReadOnly)
            }
            None => return Err(Error::NotFound),
        }
        Ok(())
    }

    /// Число одновременных сессий, которое поддерживает сервер.
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Создать сессию для нового соединения: занимает транспортный слот и
    /// возвращает [`Session`]. Сессия (с буферами `rx`/`tx`) принадлежит
    /// вызывающему, поэтому I/O канала не требует `&mut Server`.
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub fn on_connect(&mut self, media: Media) -> Result<Session, Error> {
        let transport_ref = match media {
            #[cfg(feature = "optical")]
            Media::Optical => {
                self.optical_pool.alloc().ok_or(Error::NoSlot)?;
                TransportRef::Hdlc(HdlcState::new())
            }
            #[cfg(feature = "tcp")]
            Media::Tcp => {
                self.tcp_pool.alloc().ok_or(Error::NoSlot)?;
                TransportRef::Wrapper(Wrapper::new(self.tcp_pool.source_port(), 0))
            }
            #[cfg(feature = "ble")]
            Media::Ble => {
                self.ble_pool.alloc().ok_or(Error::NoSlot)?;
                TransportRef::Wrapper(Wrapper::new(self.ble_pool.source_port(), 0))
            }
        };
        Ok(Session::new(media, transport_ref))
    }

    /// Освободить транспортный слот по закрытию соединения.
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub fn on_disconnect(&mut self, media: Media) {
        self.release(media);
    }

    /// Обслужить одно соединение: on_connect → ассоциация → цикл
    /// Get-запросов → on_disconnect.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    pub async fn serve<C: Channel<Frame = Wrapper>>(
        &mut self,
        media: Media,
        mut channel: C,
    ) -> Result<(), Error> {
        let mut session = self.on_connect(media)?;

        // Цикл обслуживания: AARQ/AARE, GET/SET, RLRQ — всё через process_request.
        // Выход по RLRQ (state = Disconnecting)/таймауту/закрытию/ошибке.
        let result = loop {
            if let Err(e) = self.handle_request(&mut session, &mut channel).await {
                break Err(e);
            }
            if session.state() == AssociationState::Disconnecting {
                break Ok(());
            }
        };

        // Всегда освобождаем слот: и при успехе, и при таймауте/ошибке.
        self.on_disconnect(session.media());
        result
    }

    /// Обработать один уже прочитанный WPDU (AARQ, xDLMS-запрос или RLRQ) из
    /// `session.rx` и сформировать ответный WPDU прямо в `session.tx`.
    /// Сетевого I/O не делает.
    ///
    /// Освобождение ассоциации (RLRQ) отражается в `session.state()`
    /// (`Disconnecting`) — вызывающий по нему решает, продолжать ли цикл.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    pub fn process_request(
        &mut self,
        session: &mut Session,
        received: Wrapper,
    ) -> Result<(), Error> {
        // Диспетчеризация по тегу APDU (класс, номер, constructed) + состояние.
        let tag = {
            let mut r = Reader::new(session.rx());
            Tag::get(&mut r).map_err(Error::Codec)?
        };

        match (tag.class, tag.number, tag.constructed, session.state()) {
            // ACSE: AARQ = [APPLICATION 0] IMPLICIT SEQUENCE.
            (Class::Application, 0, true, AssociationState::Idle) => {
                let conf = self.proposed_conformance();
                let aarq = {
                    let mut r = Reader::new(session.rx());
                    AARQapdu::get(&mut r).map_err(Error::Codec)?
                };
                let mut aare = AAREapdu::rejected_permanent();
                let ui = aarq.user_information.ok_or_else(|| {
                    Error::Codec(cosempdu::Error::Message("AARQ without user-information"))
                })?;
                let req = InitiateRequest::get(&mut Reader::new(ui)).map_err(Error::Codec)?;
                let proposed_dlms_version = req.proposed_dlms_version_number;
                let negotiated = req.proposed_conformance.intersection(conf);
                let wrapper = validate_wrapper(&session.transport_ref(), received)?;

                // Owned-поля (Copy) — извлекаем сразу, чтобы отпустить borrow
                // на session.rx() до мутабельного доступа к session.
                let ctx = aarq.application_context_name;
                match ctx {
                    ApplicationContextName::ShortNameCiphering | ApplicationContextName::ShortNameNoCiphering => {
                        aare.application_context_name = ApplicationContextName::LogicalNameNoCiphering;
                        aare.result_source_diagnostic = AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::ApplicationContextNameNotSupported);
                        session.encode_tx(|out|wrapper.put(out, |buf| aare.put(buf)).map_err(Error::Codec))?;
                        return Ok(());
                    },
                    ApplicationContextName::LogicalNameCiphering => {
                        session.ciphering = true;
                    },
                    _ => {}
                }
                let mut u_i = [0u8; 64];
                if proposed_dlms_version < DLMS_VERSION_NUMBER {
                    // Отказ: dlms-version-too-low → AARE(RejectedPermanent) +
                    // ConfirmedServiceError(initiate-error: dlms-version-too-low).
                    aare.application_context_name = ctx;
                    aare.result_source_diagnostic = AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::NoReasonGiven);
                    let cse = ConfirmedServiceError {
                        tag: confirmed_service_error_tag::INITIATE_ERROR,
                        service_error: SnServiceError::Initiate(Initiate::DlmsVersionTooLow),
                    };
                    let cse_n = cse
                        .put(&mut ByteBuffer::new(&mut u_i))
                        .map_err(Error::Codec)?;
                    aare.user_information = Some(&u_i[..cse_n]);
                    session.encode_tx(|out|wrapper.put(out, |buf| aare.put(buf)).map_err(Error::Codec))?;
                    return Ok(());
                };
               // Запомнить wPort клиента для последующих запросов.
                session.set_transport_ref(TransportRef::Wrapper(wrapper));
                session.set_state(AssociationState::Associating);

                // Закодировать AARE WPDU прямо в session.tx.
                // InitiateResponse (user-information) в scratch-буфер.
                let resp = InitiateResponse::new(negotiated, MAX_APDU as u16);
                let ir_n = resp
                    .put(&mut ByteBuffer::new(&mut u_i))
                    .map_err(Error::Codec)?;

                aare.result = AssociationResult::Accepted;
                aare.result_source_diagnostic = AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::Null);
                aare.user_information = Some(&u_i[..ir_n]);
                // WPDU-заголовок + AARE APDU прямо в tx.
                session.encode_tx(|tx| wrapper.put(tx, |buf| aare.put(buf)))?;
                session.set_conformance(negotiated);
                // Ассоциация установлена.
                session.set_state(AssociationState::Associated);
            }
            (Class::Application, 0, true, _) => {
                build_association_not_established(session)?;
            }
            // ACSE: RLRQ = [APPLICATION 2] IMPLICIT SEQUENCE.
            (Class::Application, 2, true, _) => {
                handle_release(session)?;
            }
            // xDLMS: Get-Request = [192] IMPLICIT CHOICE (ассоциация установлена).
            (Class::Private, 0, false, AssociationState::Associated) => {
                self.process_get(session)?;
            }
            // xDLMS: Set-Request = [193] IMPLICIT CHOICE (ассоциация установлена).
            (Class::Private, 1, false, AssociationState::Associated) => {
                self.process_set(session)?;
            }
            // GET/SET при неустановленной ассоциации → "Association is not established".
            (Class::Private, 0 | 1, false, _) => {
                build_association_not_established(session)?;
            }
            // Table 89. Request is not well formed
            _ => {
                build_exception_response(session)?;
            }
        }
        Ok(())
    }

    /// Get-Request (Normal, без access_selection) → Get-Response в session.tx.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn process_get(&self, session: &mut Session) -> Result<(), Error> {
        // 1) Декодируем Get-Request в owned-поля (session.rx уже содержит только APDU).
        let (invoke, descriptor) = {
            let mut r = Reader::new(session.rx());
            match GetRequest::get(&mut r).map_err(Error::Codec)? {
                GetRequest::Normal(GetRequestNormal {
                    invoke,
                    descriptor,
                    access_selection: None,
                }) => (invoke, descriptor),
                _ => return Err(Error::NotFound),
            }
        };

        // 2) Серверный взгляд на порты (Copy) для WPDU-заголовка.
        let srv = get_wrapper(session)?;

        // 3) WPDU-заголовок + Get-Response прямо в session.tx.
        session.encode_tx(|tx| srv.put(tx, |buf| self.handle_get(invoke, descriptor, buf)))?;
        Ok(())
    }

    /// Set-Request (Normal, без access_selection) → применить значение → Set-Response.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn process_set(&mut self, session: &mut Session) -> Result<(), Error> {
        // 1) Декодируем Set-Request::Normal и применяем значение к атрибуту.
        //    Ошибка доступа к данным не прерывает обработку, а уходит в Set-Response.
        let (invoke, result) = {
            let mut r = Reader::new(session.rx());
            match SetRequest::get(&mut r).map_err(Error::Codec)? {
                SetRequest::Normal(SetRequestNormal {
                    invoke,
                    descriptor,
                    access_selection: None,
                    value,
                }) => {
                    let class_id = ClassId::from_u16(descriptor.class_id).ok_or(Error::NotFound)?;
                    let obis = ObisCode::from_bytes(descriptor.instance_id);
                    let key = AttributeKey::new(obis, descriptor.attribute_id as u8);

                    // Применить значение; при Data-Access-Result вернуть его код в ответе.
                    let result = match self.stream_set(class_id, key, AccessMask::CONFIGURATOR) {
                        Ok(mut s) => {
                            s.push(value.remaining_bytes())?;
                            s.finish()?;
                            DataAccessResult::Success
                        }
                        Err(Error::DataAccessResult(code)) => code,
                        Err(e) => return Err(e),
                    };

                    (invoke, result)
                }
                _ => return Err(Error::NotFound),
            }
        };

        // 2) Серверный взгляд на порты (Copy) для WPDU-заголовка.
        let srv = get_wrapper(session)?;

        // 3) WPDU-заголовок + Set-Response прямо в session.tx.
        session.encode_tx(|tx| srv.put(tx, |buf| SetResponse::put_normal(invoke, result, buf)))?;
        Ok(())
    }

    /// Обслужить один xDLMS-запрос: прочитать WPDU в session.rx, обработать
    /// ([`Server::process_request`]) и отправить ответ из session.tx.
    /// Освобождение ассоциации отражается в `session.state()`.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    async fn handle_request<C: Channel<Frame = Wrapper>>(
        &mut self,
        session: &mut Session,
        channel: &mut C,
    ) -> Result<(), Error> {
        let received = channel.read(session.rx_mut()).await.map_err(Error::Codec)?;
        session.set_rx_len(received.apdu_len() as usize);

        self.process_request(session, received)?;

        channel.write(session.tx()).await.map_err(Error::Codec)?;
        session.clear_rx();
        Ok(())
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
    pub fn new(objects: &'static [&'static dyn InterfaceClass], conformance: Conformance) -> Self {
        Self::with_capacity(objects, conformance)
    }
}

/// Транспортный слой: валидация Wrapper-заголовка (WPDU адресован нашему wPort)
/// и построение настроек ответа (взгляд сервера: наш wPort → wPort клиента).
#[cfg(any(feature = "tcp", feature = "ble"))]
fn validate_wrapper(transport: &TransportRef, received: Wrapper) -> Result<Wrapper, Error> {
    // Собственный wPort сервера уже сохранён в TransportRef при on_connect.
    let server_port = match transport {
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

    // Настройки ответа: наш wPort → wPort клиента (из его заголовка).
    Ok(Wrapper::new(server_port, received.source_port()))
}

/// Серверный взгляд на порты (Copy) для WPDU-заголовка ответа.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn get_wrapper(session: &Session) -> Result<Wrapper, Error> {
    match session.transport_ref() {
        TransportRef::Wrapper(s) => Ok(s),
        #[cfg(feature = "optical")]
        TransportRef::Hdlc(_) => Err(Error::Codec(cosempdu::Error::Message(
            "request handling requires Wrapper channel (tcp/ble)",
        ))),
    }
}

/// Неизвестный/некорректно сформированный APDU → error-response адресату.
///
/// LN referencing — `ExceptionResponse` (service-unknown, operation-not-possible);
/// SN referencing — not used.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn build_exception_response(session: &mut Session) -> Result<(), Error> {
    // Серверный взгляд на порты (Copy) для WPDU-заголовка ответа.
    let wrapper = get_wrapper(session)?;
    let exc = ExceptionResponse {
        state_error: StateError::ServiceUnknown,
        service_error: ServiceError_::OperationNotPossible,
    };
    session.encode_tx(|tx| wrapper.put(tx, |buf| exc.put(buf)))?;
    Ok(())
}


/// LN referencing — `ExceptionResponse` (service-not-allowed, operation-not-possible).
#[cfg(any(feature = "tcp", feature = "ble"))]
fn build_association_not_established(session: &mut Session) -> Result<(), Error> {
    let wrapper = get_wrapper(session)?;
    session.encode_tx(|tx| {
        let exc = ExceptionResponse {
            state_error: StateError::ServiceNotAllowed,
            service_error: ServiceError_::OperationNotPossible,
        };
        wrapper.put(tx, |buf| exc.put(buf))
    })?;
    Ok(())
}


/// RLRQ → RLRE: подтвердить освобождение ассоциации и записать RLRE в session.tx.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn handle_release(session: &mut Session) -> Result<(), Error> {
    // Убедимся, что пришёл именно RLRQ (не AARQ/AARE/RLRE).
    let acse = ACSEApdu::get(&mut Reader::new(session.rx())).map_err(Error::Codec)?;
    match acse {
        ACSEApdu::Rlrq(_) => {}
        _ => return Err(Error::Codec(cosempdu::Error::Message("expected RLRQ"))),
    }

    // Серверный взгляд на порты (Copy) для WPDU-заголовка ответа.
    let srv = get_wrapper(session)?;

    // RLRE (reason normal) в session.tx.
    session.encode_tx(|tx| {
        let rlre = RLREapdu {
            reason: Some(ReleaseResponseReason::Normal),
            user_information: None,
        };
        srv.put(tx, |buf| rlre.put(buf))
    })?;
    session.set_state(AssociationState::Disconnecting);
    Ok(())
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
    use cosempdu::apdu::{
        CosemAttributeDescriptor, GetDataResult, GetResponseNormal, ImplicitTagged,
        InvokeIdAndPriority,
    };
    use cosempdu::apdu::Conformance;
    use cosempdu::buffer::Reader;
    use dlms1::common_data_types::{DateTime, DoubleLongUnsigned, OctetString};
    use dlms1::ic::{
        Clock, DataObject, Register, RegisterActivation, RegisterAssignmentValue, ScalUnit,
    };

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
        server
            .add_static(REG_OBJ.attr_key(2).unwrap(), &reg, reg_access())
            .unwrap();

        // 2) обработать GetRequest::Normal напрямую (owned invoke + descriptor)
        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: ClassId::Register.as_u16(),
            instance_id: REG_OBJ.obis().bytes,
            attribute_id: 2,
        };
        let mut tx = [0u8; 128];
        let tx_n = {
            let mut b = ByteBuffer::new(&mut tx);
            server.handle_get(invoke, descriptor, &mut b).unwrap()
        };

        // 3) декодировать ответ
        let resp = {
            let mut r = Reader::new(&tx[..tx_n]);
            GetResponse::get(&mut r).unwrap()
        };

        // 4) сверить
        match resp {
            GetResponse::Normal(GetResponseNormal {
                invoke,
                result: GetDataResult::Data(r),
            }) => {
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

    #[test]
    fn server_handles_get_request_missing_object() {
        // GET на несуществующий OBIS → GetResponse::Normal с DataAccessError(ObjectUnavailable).
        let mut server = Server::new(OBJECTS, CONF);

        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: ClassId::Register.as_u16(),
            instance_id: ObisCode::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff).bytes,
            attribute_id: 2,
        };
        let mut tx = [0u8; 128];
        let tx_n = {
            let mut b = ByteBuffer::new(&mut tx);
            server.handle_get(invoke, descriptor, &mut b).unwrap()
        };

        let resp = {
            let mut r = Reader::new(&tx[..tx_n]);
            GetResponse::get(&mut r).unwrap()
        };

        match resp {
            GetResponse::Normal(GetResponseNormal {
                invoke,
                result: GetDataResult::DataAccessError(code),
            }) => {
                assert_eq!(invoke.invoke_id(), 1);
                assert_eq!(code, DataAccessResult::ObjectUnavailable);
            }
            _ => panic!("expected GetResponse::Normal with DataAccessError"),
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
        let acc = Access {
            read: AccessMask::PUBLIC,
            write: AccessMask::CONFIGURATOR,
        };
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
        assert!(r
            .get(&AttributeKey::new(ObisCode::new(9, 9, 9, 9, 9, 9), 1))
            .is_none());
    }

    #[test]
    fn server_get_set_persistent() {
        let mut server = Server::new(OBJECTS, CONF);

        static SN: DoubleLongUnsigned = DoubleLongUnsigned(123456);
        let serial = SERIAL_OBJ.value();
        server
            .add_static(
                serial,
                &SN,
                Access {
                    read: AccessMask::PUBLIC,
                    write: AccessMask::CONFIGURATOR,
                },
            )
            .unwrap();

        let mut register = DoubleLongUnsigned(230000);
        let rw = REG_OBJ.value();
        server
            .add_persistent(rw, &mut register, reg_access())
            .unwrap();

        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);
        server
            .put(
                ClassId::Register,
                REG_OBJ.value(),
                AccessMask::READER,
                &mut buf,
            )
            .unwrap();
        assert_eq!(buf.extract(), &[0x06, 0x00, 0x03, 0x82, 0x70]);

        set_data(
            &mut server,
            ClassId::Register,
            REG_OBJ.value(),
            AccessMask::CONFIGURATOR,
            &Data::DoubleLongUnsigned(1),
        )
        .unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            server
                .put(
                    ClassId::Register,
                    REG_OBJ.value(),
                    AccessMask::PUBLIC,
                    &mut buf,
                )
                .unwrap();
            assert_eq!(buf.extract(), &[0x06, 0x00, 0x00, 0x00, 0x01]);
        }

        assert_eq!(
            server.put(
                ClassId::Register,
                REG_OBJ.value(),
                AccessMask(1 << 3),
                &mut buf
            ),
            Err(Error::AccessDenied)
        );
        assert_eq!(
            set_data(
                &mut server,
                ClassId::Register,
                REG_OBJ.value(),
                AccessMask::PUBLIC,
                &Data::DoubleLongUnsigned(2)
            ),
            Err(Error::DataAccessResult(
                DataAccessResult::ScopeOfAccessViolated
            ))
        );
        assert!(set_data(
            &mut server,
            ClassId::Register,
            REG_OBJ.value(),
            AccessMask::CONFIGURATOR,
            &Data::Unsigned(200)
        )
        .is_err());
        assert_eq!(
            set_data(
                &mut server,
                ClassId::Data,
                SERIAL_OBJ.value(),
                AccessMask::CONFIGURATOR,
                &Data::Unsigned(0)
            ),
            Err(Error::DataAccessResult(DataAccessResult::ReadWriteDenied))
        );

        let missing = ObisCode::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        assert_eq!(
            server.put(
                ClassId::Register,
                AttributeKey::new(missing, 2),
                AccessMask::PUBLIC,
                &mut buf
            ),
            Err(Error::DataAccessResult(DataAccessResult::ObjectUnavailable))
        );
        assert_eq!(
            set_data(
                &mut server,
                ClassId::Register,
                AttributeKey::new(missing, 2),
                AccessMask::PUBLIC,
                &Data::NullData
            ),
            Err(Error::DataAccessResult(DataAccessResult::ObjectUnavailable))
        );
    }

    #[test]
    fn server_dynamic_update() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut clock_time = DateTime([0; 12]);
        server
            .add_dynamic(CLOCK_OBJ.time(), &mut clock_time, reg_access())
            .unwrap();

        let t: [u8; 12] = [
            0x07, 0xE8, 0x0A, 0x09, 0x00, 0x0F, 0x2A, 0x00, 0x00, 0x00, 0x00, 0xFF,
        ];
        server.update(CLOCK_OBJ.time(), &Data::DateTime(t)).unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            server
                .put(
                    ClassId::Clock,
                    CLOCK_OBJ.time(),
                    AccessMask::PUBLIC,
                    &mut buf,
                )
                .unwrap();
            assert_eq!(
                buf.extract(),
                &[0x19, 0x07, 0xE8, 0x0A, 0x09, 0x00, 0x0F, 0x2A, 0x00, 0x00, 0x00, 0x00, 0xFF]
            );
        }

        assert_eq!(
            set_data(
                &mut server,
                ClassId::Clock,
                CLOCK_OBJ.time(),
                AccessMask::CONFIGURATOR,
                &Data::DateTime(t)
            ),
            Err(Error::DataAccessResult(DataAccessResult::ReadWriteDenied))
        );

        let mut p = ScalUnit {
            scaler: 0,
            unit: 255,
        };
        let pkey = REG_OBJ.scaler_unit();
        server.add_persistent(pkey, &mut p, reg_access()).unwrap();
        assert_eq!(
            server.update(
                REG_OBJ.scaler_unit(),
                &Data::Structure(&[Data::Integer(0), Data::Enum(255)])
            ),
            Err(Error::ReadOnly)
        );
    }

    #[test]
    fn server_stream_set_scalar() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut register = DoubleLongUnsigned(0);
        let key = REG_OBJ.value();
        server
            .add_persistent(key, &mut register, reg_access())
            .unwrap();

        // Encode DoubleLongUnsigned(42) = [tag 6, 0x00, 0x00, 0x00, 0x2A].
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            Data::DoubleLongUnsigned(42).put(&mut buf).unwrap()
        };

        {
            let mut s = server
                .stream_set(ClassId::Register, key, AccessMask::CONFIGURATOR)
                .unwrap();
            let mid = n / 2;
            s.push(&backing[..mid]).unwrap();
            s.push(&backing[mid..n]).unwrap();
            s.finish().unwrap();
        }

        let mut out = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut out);
        server
            .put(ClassId::Register, key, AccessMask::PUBLIC, &mut buf)
            .unwrap();
        assert_eq!(buf.extract(), &[0x06, 0x00, 0x00, 0x00, 0x2A]);
    }

    #[test]
    fn server_stream_set_composite() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut scal = ScalUnit {
            scaler: 0,
            unit: 255,
        };
        let key = REG_OBJ.scaler_unit();
        server.add_persistent(key, &mut scal, reg_access()).unwrap();

        // Encode Structure(Integer(3), Enum(1)).
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            Data::Structure(&[Data::Integer(3), Data::Enum(1)])
                .put(&mut buf)
                .unwrap()
        };

        {
            let mut s = server
                .stream_set(ClassId::Register, key, AccessMask::CONFIGURATOR)
                .unwrap();
            s.push(&backing[..n]).unwrap();
            s.finish().unwrap();
        }

        let mut out = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut out);
        server
            .put(ClassId::Register, key, AccessMask::PUBLIC, &mut buf)
            .unwrap();
        assert_eq!(buf.extract(), &[0x02, 0x02, 0x0F, 0x03, 0x16, 0x01]);
    }

    #[test]
    fn server_stream_set_blob() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut value: OctetString<60> = OctetString::default();
        let key = REG_OBJ.value();
        server
            .add_persistent(key, &mut value, reg_access())
            .unwrap();

        // ~60-байтный octet-string, детерминированный паттерн (без heap).
        let content: [u8; 60] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
        let mut backing = [0u8; 128];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            Data::OctetString(&content).put(&mut b).unwrap()
        };

        {
            let mut s = server
                .stream_set(ClassId::Register, key, AccessMask::CONFIGURATOR)
                .unwrap();
            for chunk in backing[..n].chunks(20) {
                s.push(chunk).unwrap();
            }
            s.finish().unwrap();
        }

        let mut out = [0u8; 128];
        let mut buf = ByteBuffer::new(&mut out);
        server
            .put(ClassId::Register, key, AccessMask::PUBLIC, &mut buf)
            .unwrap();
        assert_eq!(buf.extract(), &backing[..n]);
    }

    #[test]
    fn server_validate_structure() {
        let mut server = Server::new(OBJECTS, CONF);
        let mut scal = ScalUnit { scaler: 3, unit: 1 };
        let key = REG_OBJ.scaler_unit();
        server.add_persistent(key, &mut scal, reg_access()).unwrap();

        set_data(
            &mut server,
            ClassId::Register,
            REG_OBJ.scaler_unit(),
            AccessMask::CONFIGURATOR,
            &Data::Structure(&[Data::Integer(7), Data::Enum(2)]),
        )
        .unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            server
                .put(
                    ClassId::Register,
                    REG_OBJ.scaler_unit(),
                    AccessMask::PUBLIC,
                    &mut buf,
                )
                .unwrap();
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
        server
            .add_persistent(key, &mut register, reg_access())
            .unwrap();

        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);

        server
            .put(
                ClassId::Register,
                REG_OBJ.value(),
                AccessMask::PUBLIC,
                &mut buf,
            )
            .unwrap();

        assert!(matches!(
            server.put(
                ClassId::Clock,
                REG_OBJ.value(),
                AccessMask::PUBLIC,
                &mut buf
            ),
            Err(Error::DataAccessResult(
                DataAccessResult::ObjectClassInconsistent
            ))
        ));

        let unknown = ObisCode::new(9, 9, 9, 9, 9, 9);
        assert_eq!(
            server.put(
                ClassId::Register,
                AttributeKey::new(unknown, 2),
                AccessMask::PUBLIC,
                &mut buf
            ),
            Err(Error::DataAccessResult(DataAccessResult::ObjectUnavailable))
        );
    }

    #[test]
    fn server_register_activation_register_assignment() {
        // 1. Полностью настраиваем сервер.
        let mut server = Server::new(OBJECTS, CONF);
        let key = RA_OBJ.register_assignment();
        let mut value = RegisterAssignmentValue::<2>::default();
        server
            .add_persistent(key, &mut value, reg_access())
            .unwrap();

        // 2. Кодируем array из 2 object_definition.
        let ln0 = ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL; // 1.0.1.8.0.255
        let ln1 = ObisCode::ACTIVE_ENERGY_EXPORT_TOTAL; // 1.0.2.8.0.255
        let f0 = [
            Data::LongUnsigned(ClassId::Register.as_u16()),
            Data::OctetString(&ln0.bytes),
        ];
        let f1 = [
            Data::LongUnsigned(ClassId::ExtendedRegister.as_u16()),
            Data::OctetString(&ln1.bytes),
        ];
        let items = [Data::Structure(&f0), Data::Structure(&f1)];
        let mut backing = [0u8; 128];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            Data::Array(&items).put(&mut b).unwrap()
        };

        // 3. Потоковый приём за 3 прохода через сервер.
        {
            let mut s = server
                .stream_set(ClassId::RegisterActivation, key, AccessMask::CONFIGURATOR)
                .unwrap();
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
        server
            .put(
                ClassId::RegisterActivation,
                key,
                AccessMask::PUBLIC,
                &mut buf,
            )
            .unwrap();
        assert_eq!(
            buf.extract(),
            &[
                0x01, 0x02, // array {2}
                0x02, 0x02, 0x12, 0x00, 0x03, 0x09, 0x06, 0x01, 0x00, 0x01, 0x08, 0x00,
                0xFF, // {Register, 1.0.1.8.0.255}
                0x02, 0x02, 0x12, 0x00, 0x04, 0x09, 0x06, 0x01, 0x00, 0x02, 0x08, 0x00,
                0xFF, // {ExtendedRegister, 1.0.2.8.0.255}
            ]
        );
    }

    #[test]
    fn memory_sizes() {
        use core::mem::size_of;
        let entry = size_of::<Option<(AttributeKey, ValueRef<'static>)>>();
        let registry = size_of::<Registry<'static>>();

        println!(
            "AccessMask                  = {} B",
            size_of::<AccessMask>()
        );
        println!("Access                      = {} B", size_of::<Access>());
        println!(
            "AttributeKey                = {} B",
            size_of::<AttributeKey>()
        );
        println!(
            "ValueRef<'static>           = {} B",
            size_of::<ValueRef<'static>>()
        );
        println!("entry Option<(key, ValueRef)> = {} B", entry);
        println!(
            "Registry<'static>           = {} B ({} slots)",
            registry, MAX_ATTRS
        );
        println!(
            "Server<'static, 3>          = {} B",
            size_of::<Server<'static>>()
        );
        println!(
            "registry per 1000 attrs     = {} B ~ {} KB",
            entry * 1000,
            entry * 1000 / 1024
        );
    }
}

#[cfg(all(test, feature = "optical"))]
mod transport_tests {
    use crate::{Error, Media, Server, RX_BUF};
    use cosempdu::apdu::Conformance;
    use dlms1::ic::InterfaceClass;

    const CONF: Conformance = Conformance([0x00, 0x7E, 0x1F]);

    static NO_OBJECTS: &[&dyn InterfaceClass] = &[];

    #[test]
    fn connect_disconnect_and_slot_reuse() {
        let mut server: Server = Server::new(NO_OBJECTS, CONF);

        let s0 = server.on_connect(Media::Optical).unwrap();
        let _s1 = server.on_connect(Media::Optical).unwrap();
        let _s2 = server.on_connect(Media::Optical).unwrap();

        // Лимит слотов пула оптики (N = 3) исчерпан.
        assert!(matches!(
            server.on_connect(Media::Optical),
            Err(Error::NoSlot)
        ));

        // Освобождение слота возвращает его в пул.
        server.on_disconnect(s0.media());
        let _s3 = server.on_connect(Media::Optical).unwrap();
    }

    #[test]
    fn data_accumulates_and_overflow() {
        let mut server: Server = Server::new(NO_OBJECTS, CONF);
        let mut s = server.on_connect(Media::Optical).unwrap();

        assert!(s.push_rx(&[1, 2, 3]));
        assert_eq!(s.rx(), &[1, 2, 3]);

        // Переполнение rx-буфера (push_rx возвращает false).
        let big = [0u8; RX_BUF + 1];
        assert!(!s.push_rx(&big));
    }
}

#[cfg(all(test, any(feature = "tcp", feature = "ble")))]
mod wrapper_tests {
    use crate::{Media, Server, TransportRef, Wrapper};
    use cosempdu::acse::{ACSEApdu, RLRQapdu, ReleaseRequestReason, ReleaseResponseReason};
    use cosempdu::apdu::Conformance;
    use cosempdu::buffer::{ByteBuffer, Reader};
    use dlms1::ic::InterfaceClass;

    const CONF: Conformance = Conformance([0x00, 0x7E, 0x1F]);
    static NO_OBJECTS: &[&dyn InterfaceClass] = &[];

    #[test]
    fn wrapper_put_get_roundtrip() {
        let setting = Wrapper::new(0, 0x1234);

        let apdu = [0x0F, 0x01, 0x02, 0x03];
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            setting.put(&mut buf, |b| b.write(&apdu)).unwrap()
        };

        let mut reader = Reader::new(&backing[..n]);
        let decoded = Wrapper::get(&mut reader).unwrap();
        assert_eq!(decoded.apdu_len() as usize, apdu.len());
        assert_eq!(decoded.destination_port(), 0x1234);
        assert_eq!(decoded.source_port(), 0);
        assert_eq!(reader.read(decoded.apdu_len() as usize).unwrap(), &apdu[..]);
    }

    /// RLRQ (release-request) → RLRE (normal) + признак освобождения ассоциации.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_rlrq() {
        use crate::AssociationState;

        let mut server: Server = Server::new(NO_OBJECTS, CONF);
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();
        // Состояние после AARQ: src=сервер(1) → dst=клиент(16).
        session.set_transport_ref(TransportRef::Wrapper(Wrapper::new(1, 16)));

        // RLRQ APDU (reason normal).
        let mut backing = [0u8; 16];
        let apdu_n = {
            let mut b = ByteBuffer::new(&mut backing);
            RLRQapdu {
                reason: Some(ReleaseRequestReason::Normal),
                user_information: None,
            }
            .put(&mut b)
            .unwrap()
        };
        session.rx_mut()[..apdu_n].copy_from_slice(&backing[..apdu_n]);
        session.set_rx_len(apdu_n);

        // Должен записать RLRE в tx и перевести сессию в Disconnecting.
        server
            .process_request(&mut session, Wrapper::new(16, 1))
            .unwrap();
        assert_eq!(session.state(), AssociationState::Disconnecting);

        // Ответ: WPDU-заголовок + RLRE.
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
            ACSEApdu::Rlre(r) => assert_eq!(r.reason, Some(ReleaseResponseReason::Normal)),
            other => panic!("expected RLRE, got {other:?}"),
        }
    }

    /// AARQ → AARE + Session.state = Associated.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_aarq() {
        use crate::AssociationState;
        use cosempdu::acse::{AARQapdu, ApplicationContextName, AssociationResult};
        use cosempdu::apdu::InitiateRequest;

        let mut server: Server = Server::new(NO_OBJECTS, CONF);
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();

        // AARQ APDU.
        let req = InitiateRequest::new(CONF, 1200);
        let mut ui = [0u8; 64];
        let n = req.put(&mut ByteBuffer::new(&mut ui)).unwrap();
        let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        aarq.user_information = Some(&ui[..n]);
        let mut apdu = [0u8; 256];
        let m = aarq.put(&mut ByteBuffer::new(&mut apdu)).unwrap();
        session.rx_mut()[..m].copy_from_slice(&apdu[..m]);
        session.set_rx_len(m);

        // received: клиент (src=16) → сервер (dst=1).
        server
            .process_request(&mut session, Wrapper::new(16, 1))
            .unwrap();
        assert_eq!(session.state(), AssociationState::Associated);

        // Ответ: AARE (accepted).
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
            ACSEApdu::Aare(a) => assert_eq!(a.result, AssociationResult::Accepted),
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// AARQ с version-too-low → AARE(RejectedPermanent) + ConfirmedServiceError(initiate: dlms-version-too-low).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_rejects_dlms_version_too_low() {
        use crate::AssociationState;
        use cosempdu::acse::{
            AARQapdu, AcseServiceUser, ApplicationContextName, AssociateSourceDiagnostic,
            AssociationResult,
        };
        use cosempdu::apdu::{
            confirmed_service_error_tag, ConfirmedServiceError, ImplicitTagged, Initiate,
            InitiateRequest, SnServiceError,
        };

        let mut server: Server = Server::new(NO_OBJECTS, CONF);
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();

        // AARQ APDU с proposed_dlms_version_number = 5 (< 6).
        let req = InitiateRequest {
            dedicated_key: None,
            response_allowed: true,
            proposed_dlms_version_number: 5,
            proposed_conformance: CONF,
            client_max_receive_pdu_size: 1200,
        };
        let mut ui = [0u8; 64];
        let n = req.put(&mut ByteBuffer::new(&mut ui)).unwrap();
        let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        aarq.user_information = Some(&ui[..n]);
        let mut apdu = [0u8; 256];
        let m = aarq.put(&mut ByteBuffer::new(&mut apdu)).unwrap();
        session.rx_mut()[..m].copy_from_slice(&apdu[..m]);
        session.set_rx_len(m);

        // received: клиент (src=16) → сервер (dst=1).
        server
            .process_request(&mut session, Wrapper::new(16, 1))
            .unwrap();

        // Ассоциация НЕ установлена (остаёмся в Idle).
        assert_eq!(session.state(), AssociationState::Idle);

        // Ответ: AARE (rejected-permanent) + ConfirmedServiceError(initiate: dlms-version-too-low).
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
            ACSEApdu::Aare(a) => {
                assert_eq!(a.result, AssociationResult::RejectedPermanent);
                assert_eq!(
                    a.result_source_diagnostic,
                    AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::NoReasonGiven)
                );
                let ui = a.user_information.expect("AARE with user-information");
                let cse = ConfirmedServiceError::get(&mut Reader::new(ui)).unwrap();
                assert_eq!(cse.tag, confirmed_service_error_tag::INITIATE_ERROR);
                assert_eq!(
                    cse.service_error,
                    SnServiceError::Initiate(Initiate::DlmsVersionTooLow)
                );
            }
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// Неизвестный APDU-тег (LN) → ExceptionResponse (service-unknown, operation-not-possible).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_unknown_tag_ln() {
        use cosempdu::apdu::{ExceptionResponse, ImplicitTagged, ServiceError_, StateError};

        let mut server: Server = Server::new(NO_OBJECTS, CONF);
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.set_transport_ref(TransportRef::Wrapper(Wrapper::new(1, 16)));

        // Тег [2] context-specific primitive — не GetRequest/SetRequest/ACSE.
        session.rx_mut()[0] = 0x82;
        session.set_rx_len(1);

        server
            .process_request(&mut session, Wrapper::new(16, 1))
            .unwrap();

        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        let exc = ExceptionResponse::get(&mut Reader::new(apdu)).unwrap();
        assert_eq!(exc.state_error, StateError::ServiceUnknown);
        assert_eq!(exc.service_error, ServiceError_::OperationNotPossible);
    }


    /// Get-Request при неустановленной ассоциации → "Association is not established"
    /// (LN: exception-response service-not-allowed / operation-not-possible).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_rejects_get_without_association_ln() {
        use cosempdu::apdu::{ExceptionResponse, ImplicitTagged, ServiceError_, StateError};

        let mut server: Server = Server::new(NO_OBJECTS, CONF);
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.set_transport_ref(TransportRef::Wrapper(Wrapper::new(1, 16)));
        // state = Idle — ассоциация не установлена.

        session.rx_mut()[0] = 0xC0; // Get-Request [192]
        session.set_rx_len(1);

        server
            .process_request(&mut session, Wrapper::new(16, 1))
            .unwrap();

        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        let exc = ExceptionResponse::get(&mut Reader::new(apdu)).unwrap();
        assert_eq!(exc.state_error, StateError::ServiceNotAllowed);
        assert_eq!(exc.service_error, ServiceError_::OperationNotPossible);
    }

    /// Set-Request::Normal → значение применяется к атрибуту, в ответе — null-data.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_set() {
        use crate::{Access, AccessMask, AssociationState};
        use cosempdu::apdu::{
            CosemAttributeDescriptor, DataAccessResult, ImplicitTagged, InvokeIdAndPriority, SetRequest,
            SetResponse, SetResponseNormal,
        };
        use dlms1::common_data_types::DoubleLongUnsigned;
        use dlms1::ic::Register;
        use dlms1::obis::ObisCode;

        static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
        static OBJECTS: &[&dyn InterfaceClass] = &[&REG_OBJ];

        let mut server: Server = Server::new(OBJECTS, CONF);
        server.set_wport(1);
        let mut register = DoubleLongUnsigned(0);
        server
            .add_persistent(
                REG_OBJ.value(),
                &mut register,
                Access {
                    read: AccessMask::PUBLIC,
                    write: AccessMask::CONFIGURATOR,
                },
            )
            .unwrap();
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.set_transport_ref(TransportRef::Wrapper(Wrapper::new(1, 16)));
        session.set_state(AssociationState::Associated);

        // Set-Request::Normal: value = DoubleLongUnsigned(7).
        let invoke = InvokeIdAndPriority::from_bits(2, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: REG_OBJ.class_id().as_u16(),
            instance_id: REG_OBJ.obis().bytes,
            attribute_id: 2,
        };
        let value = DoubleLongUnsigned(7);
        let mut backing = [0u8; 128];
        let apdu_n = {
            let mut b = ByteBuffer::new(&mut backing);
            SetRequest::put_normal(invoke, descriptor, None, &value, &mut b).unwrap()
        };
        session.rx_mut()[..apdu_n].copy_from_slice(&backing[..apdu_n]);
        session.set_rx_len(apdu_n);

        // Обработать: вернуть true (продолжать), атрибут обновлён.
        server
            .process_request(&mut session, Wrapper::new(16, 1))
            .unwrap();
        assert_eq!(register.0, 7);

        // Ответ: SetResponse::Normal (success).
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match SetResponse::get(&mut Reader::new(apdu)).unwrap() {
            SetResponse::Normal(SetResponseNormal {
                invoke,
                result: DataAccessResult::Success,
            }) => {
                assert_eq!(invoke.invoke_id(), 2);
            }
            other => panic!("expected SetResponse::Normal with success, got {other:?}"),
        }
    }

    /// Set-Request на read-only атрибут → SetResponse::Normal с ReadWriteDenied (не прерывает).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_set_readonly() {
        use crate::{Access, AccessMask, AssociationState};
        use cosempdu::apdu::{
            CosemAttributeDescriptor, DataAccessResult, ImplicitTagged, InvokeIdAndPriority, SetRequest,
            SetResponse, SetResponseNormal,
        };
        use dlms1::common_data_types::DoubleLongUnsigned;
        use dlms1::ic::Register;
        use dlms1::obis::ObisCode;

        static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
        static OBJECTS: &[&dyn InterfaceClass] = &[&REG_OBJ];

        let mut server: Server = Server::new(OBJECTS, CONF);
        server.set_wport(1);
        let register = DoubleLongUnsigned(0);
        server
            .add_static(
                REG_OBJ.value(),
                &register,
                Access {
                    read: AccessMask::PUBLIC,
                    write: AccessMask::CONFIGURATOR,
                },
            )
            .unwrap();
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.set_transport_ref(TransportRef::Wrapper(Wrapper::new(1, 16)));
        session.set_state(AssociationState::Associated);

        // Set-Request::Normal: value = DoubleLongUnsigned(7).
        let invoke = InvokeIdAndPriority::from_bits(2, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: REG_OBJ.class_id().as_u16(),
            instance_id: REG_OBJ.obis().bytes,
            attribute_id: 2,
        };
        let value = DoubleLongUnsigned(7);
        let mut backing = [0u8; 128];
        let apdu_n = {
            let mut b = ByteBuffer::new(&mut backing);
            SetRequest::put_normal(invoke, descriptor, None, &value, &mut b).unwrap()
        };
        session.rx_mut()[..apdu_n].copy_from_slice(&backing[..apdu_n]);
        session.set_rx_len(apdu_n);

        // Обработать: не прерывать (true); в ответе — ReadWriteDenied.
        server
            .process_request(&mut session, Wrapper::new(16, 1))
            .unwrap();

        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match SetResponse::get(&mut Reader::new(apdu)).unwrap() {
            SetResponse::Normal(SetResponseNormal {
                invoke,
                result: DataAccessResult::ReadWriteDenied,
            }) => {
                assert_eq!(invoke.invoke_id(), 2);
            }
            other => panic!("expected SetResponse::Normal with ReadWriteDenied, got {other:?}"),
        }
    }
}
