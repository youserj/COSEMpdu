//! Транспортные каналы DLMS/COSEM (no_alloc).
//!
//! Физические каналы подключаются фичами Cargo `optical`, `tcp`, `ble`.
//! У каждого канала — собственный пул слотов с независимым состоянием.

#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::buffer::{ByteBuffer, Reader};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::error::{Error, Result};

/// Максимальный размер xDLMS APDU (без транспортного заголовка).
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub const MAX_APDU: usize = 1024;

/// Запас под транспортный заголовок поверх `MAX_APDU`.
///
/// COSEM Wrapper: version(2) + source wPort(2) + destination wPort(2) +
/// length(2) = 8 байт; HDLC добавляет address/control/FCS.
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub const TRANSPORT_OVERHEAD: usize = 8;

/// Версия COSEM Wrapper-заголовка (всегда 1).
#[cfg(any(feature = "tcp", feature = "ble"))]
pub const WRAPPER_VERSION: u16 = 1;

/// Физический носитель, по которому приходит соединение.
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Media {
    #[cfg(feature = "optical")]
    Optical,
    #[cfg(feature = "tcp")]
    Tcp,
    #[cfg(feature = "ble")]
    Ble,
}

/// Настройки текущего соединения (2 вида: HDLC и Wrapper).
///
/// В отличие от простого индекса слота, хранит состояние/настройки канала
/// прямо в сессии: для Wrapper — согласованный [`WrapperSetting`] (порты), для
/// оптического порта — [`HdlcState`] (счётчики HDLC).
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportRef {
    #[cfg(feature = "optical")]
    Hdlc(HdlcState),
    #[cfg(any(feature = "tcp", feature = "ble"))]
    Wrapper(WrapperSetting),
}

// ---------------------------------------------------------------------------
// COSEM Wrapper (TCP/BLE): настройки подключения + кодек WPDU-заголовка
// ---------------------------------------------------------------------------

/// Настройки Wrapper-подключения (значение, которое кодирует/декодирует [`Wrapper`]).
#[cfg(any(feature = "tcp", feature = "ble"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapperSetting {
    source_port: u16,      // собственный wPort сервера (фиксирован)
    destination_port: u16, // wPort клиента (меняется на каждое подключение)
    apdu_len: u16,         // length из WPDU-заголовка (заполняется при `get`)
    mtu: u16,              // только BLE (сегментация); TCP не использует
}

#[cfg(any(feature = "tcp", feature = "ble"))]
impl WrapperSetting {
    pub const fn new(source_port: u16) -> Self {
        Self { source_port, destination_port: 0, apdu_len: 0, mtu: 20 }
    }

    /// Собственный wPort сервера (фиксирован для всех подключений).
    pub fn source_port(&self) -> u16 { self.source_port }

    /// wPort клиента (меняется на каждое подключение).
    pub fn destination_port(&self) -> u16 { self.destination_port }

    /// Задать wPort клиента для текущего подключения.
    pub fn set_destination_port(&mut self, port: u16) { self.destination_port = port; }

    /// Длина APDU из WPDU-заголовка (заполняется при `get`).
    pub fn apdu_len(&self) -> u16 { self.apdu_len }

    /// Согласованный MTU (только BLE; для TCP не используется).
    pub fn mtu(&self) -> u16 { self.mtu }

    /// Задать MTU для текущего подключения (BLE).
    pub fn set_mtu(&mut self, mtu: u16) { self.mtu = mtu; }
}

/// Кодек COSEM Wrapper (аналог `Codec` из `cosempdu::data`): только байтовый
/// формат WPDU-заголовка. APDU передаётся отдельно как payload.
#[cfg(any(feature = "tcp", feature = "ble"))]
pub trait Wrapper: Sized {
    fn source_port(&self) -> u16;
    fn destination_port(&self) -> u16;
    fn set_destination_port(&mut self, port: u16);

    /// Закодировать WPDU целиком (заголовок + `apdu`) в `buf`.
    fn put(&self, apdu: &[u8], buf: &mut ByteBuffer<'_>) -> Result<usize> {
        let mut n = buf.put_u16(WRAPPER_VERSION)?;
        n += buf.put_u16(self.source_port())?;
        n += buf.put_u16(self.destination_port())?;
        n += buf.put_u16(apdu.len() as u16)?;
        n += buf.write(apdu)?;
        Ok(n)
    }

    /// Декодировать WPDU-заголовок; длина APDU — в `Self::apdu_len`.
    fn get(reader: &mut Reader<'_>) -> Result<Self>;
}

#[cfg(any(feature = "tcp", feature = "ble"))]
impl Wrapper for WrapperSetting {
    fn source_port(&self) -> u16 { self.source_port }
    fn destination_port(&self) -> u16 { self.destination_port }
    fn set_destination_port(&mut self, port: u16) { self.destination_port = port; }

    fn get(reader: &mut Reader<'_>) -> Result<Self> {
        if reader.get_u16()? != WRAPPER_VERSION {
            return Err(Error::Message("unsupported Wrapper version"));
        }
        let source_port = reader.get_u16()?;
        let destination_port = reader.get_u16()?;
        let apdu_len = reader.get_u16()?;
        Ok(Self { source_port, destination_port, apdu_len, mtu: 20 })
    }
}

// ---------------------------------------------------------------------------
// HDLC (оптический порт)
// ---------------------------------------------------------------------------

#[cfg(feature = "optical")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HdlcState {
    pub send_seq: u8,
    pub recv_seq: u8,
    pub window: u8,
}

#[cfg(feature = "optical")]
impl HdlcState {
    pub const fn new() -> Self {
        Self { send_seq: 0, recv_seq: 0, window: 1 }
    }
}

// ---------------------------------------------------------------------------
// Пулы (только для включённых фич)
// ---------------------------------------------------------------------------

/// Счётчик занятых HDLC-слотов (состояние канала — в `TransportRef::Hdlc`).
///
/// `N` — лимит слотов (совпадает с числом сессий `Server::<N>`).
#[cfg(feature = "optical")]
pub struct HdlcPool<const N: usize> {
    used: usize,
}

#[cfg(feature = "optical")]
impl<const N: usize> HdlcPool<N> {
    pub const fn new() -> Self {
        Self { used: 0 }
    }

    /// Занять слот; `None`, если достигнут лимит `N`.
    pub fn alloc(&mut self) -> Option<()> {
        if self.used < N {
            self.used += 1;
            Some(())
        } else {
            None
        }
    }

    /// Освободить слот.
    pub fn free(&mut self) {
        if self.used > 0 {
            self.used -= 1;
        }
    }
}

/// Счётчик занятых Wrapper-слотов (TCP/BLE). Настройки соединения хранятся в
/// `TransportRef::Wrapper`; здесь — лимит и собственный wPort сервера.
#[cfg(any(feature = "tcp", feature = "ble"))]
pub struct WrapperPool<const N: usize> {
    source_port: u16,
    used: usize,
}

#[cfg(any(feature = "tcp", feature = "ble"))]
impl<const N: usize> WrapperPool<N> {
    pub const fn new(source_port: u16) -> Self {
        Self { source_port, used: 0 }
    }

    /// Собственный wPort сервера (фиксирован для всех подключений канала).
    pub fn source_port(&self) -> u16 { self.source_port }

    /// Переопределить собственный wPort сервера (до приёма соединений).
    pub fn set_source_port(&mut self, port: u16) { self.source_port = port; }

    /// Занять слот; `None`, если достигнут лимит `N`.
    pub fn alloc(&mut self) -> Option<()> {
        if self.used < N {
            self.used += 1;
            Some(())
        } else {
            None
        }
    }

    /// Освободить слот.
    pub fn free(&mut self) {
        if self.used > 0 {
            self.used -= 1;
        }
    }
}
