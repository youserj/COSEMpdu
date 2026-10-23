//! Сессия DLMS/COSEM — общая для всех транспортных каналов.

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
use crate::transport::{Media, TransportRef, MAX_APDU, TRANSPORT_OVERHEAD};
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
use cosempdu::apdu_sn::Conformance;
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
use cosempdu::buffer::{ArrayBuffer, ByteBuffer, Reader};

/// Размер буфера обмена сессии (APDU + транспортный заголовок).
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub const RX_BUF: usize = MAX_APDU + TRANSPORT_OVERHEAD;

/// Состояния DLMS/COSEM-ассоциации.
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationState {
    Idle,
    Associating,
    Associated,
    Disconnecting,
}

/// Сессия: ссылка на транспортный слот, согласованный conformance и
/// собственные буферы обмена (rx — приём, tx — передача).
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub struct Session {
    /// Канал, по которому открыто соединение (для освобождения счётчика в `release`).
    media: Media,
    /// Настройки/состояние транспортного канала текущего соединения.
    transport_ref: TransportRef,
    /// Согласованный conformance (результат AARQ/AARE для этой ассоциации).
    conformance: Conformance,
    state: AssociationState,
    invoke_id: u8,
    rx: ArrayBuffer<RX_BUF>,
    tx: ArrayBuffer<RX_BUF>,
}

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
impl Session {
    pub const fn new(media: Media, transport_ref: TransportRef) -> Self {
        Self {
            media,
            transport_ref,
            conformance: Conformance([0; 3]),
            state: AssociationState::Idle,
            invoke_id: 0,
            rx: ArrayBuffer::new(),
            tx: ArrayBuffer::new(),
        }
    }

    pub fn media(&self) -> Media { self.media }
    pub fn transport_ref(&self) -> TransportRef { self.transport_ref }

    /// Обновить настройки соединения (например, сохранить wPort клиента после
    /// разбора WPDU-заголовка).
    pub fn set_transport_ref(&mut self, t: TransportRef) { self.transport_ref = t; }
    pub fn state(&self) -> AssociationState { self.state }
    pub fn conformance(&self) -> Conformance { self.conformance }
    pub fn invoke_id(&self) -> u8 { self.invoke_id }

    /// Накопленные байты приёма (срез до текущей позиции).
    pub fn rx(&self) -> &[u8] { self.rx.extract() }

    /// Длина накопленных данных приёма.
    pub fn rx_len(&self) -> usize { self.rx.pos() }

    /// Транзиентный `Reader` поверх принятых байт.
    pub fn reader(&self) -> Reader<'_> { Reader::new(self.rx.extract()) }

    /// Полный rx-буфер для чтения из канала (затем `set_rx_len`).
    pub fn rx_mut(&mut self) -> &mut [u8] { self.rx.as_bytes_mut() }

    /// Задать длину валидных байт приёма.
    pub fn set_rx_len(&mut self, len: usize) { let _ = self.rx.set_pos(len); }

    /// Байты ответа (срез до текущей позиции).
    pub fn tx(&self) -> &[u8] { self.tx.extract() }

    /// Длина байт ответа.
    pub fn tx_len(&self) -> usize { self.tx.pos() }

    /// Транзиентный `ByteBuffer` для записи ответа (затем `set_tx_len`).
    pub fn tx_buffer(&mut self) -> ByteBuffer<'_> { ByteBuffer::new(self.tx.as_bytes_mut()) }

    /// Задать длину валидных байт ответа.
    pub fn set_tx_len(&mut self, len: usize) { let _ = self.tx.set_pos(len); }

    /// Добавить байты в rx-буфер. Возвращает `false` при переполнении.
    pub fn push_rx(&mut self, data: &[u8]) -> bool {
        if self.rx.remaining() < data.len() {
            return false;
        }
        self.rx.write(data).is_ok()
    }

    /// Сбросить rx-буфер (после обработки кадра).
    pub fn clear_rx(&mut self) { self.rx.clear(); }
}
