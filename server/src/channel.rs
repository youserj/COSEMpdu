//! Асинхронные транспортные каналы (no_alloc).
//!
//! Канал двигает полный WPDU между физическим носителем и буферами [`Session`].
//! Используется нативный `async fn in trait` (без `async-trait`-крейта, без
//! `alloc`) — статическая диспетчеризация через дженерики.

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
use cosempdu::error::Error;

/// Асинхронный канал связи: читает/пишет полный WPDU (с фреймингом).
///
/// `Frame` — метаданные принятого кадра (например, `WrapperSetting` для TCP/BLE;
/// для будущего HDLC-канала — свой тип кадра). Это точка обобщения под HDLC.
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
#[allow(async_fn_in_trait)]
pub trait Channel {
    /// Метаданные принятого кадра (заголовок, длина payload).
    type Frame;

    /// Прочитать один полный WPDU из носителя в `buf`, вернуть метаданные кадра.
    async fn read(&mut self, buf: &mut [u8]) -> Result<Self::Frame, Error>;

    /// Записать `data` (WPDU) в носитель.
    async fn write(&mut self, data: &[u8]) -> Result<(), Error>;
}

/// Асинхронный приёмник соединений (например, TCP listener).
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
#[allow(async_fn_in_trait)]
pub trait Listener {
    type Channel: Channel;

    /// Принять одно входящее соединение и вернуть его канал.
    async fn accept(&mut self) -> Result<Self::Channel, Error>;
}
