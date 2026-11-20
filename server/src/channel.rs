//! Asynchronous transport channels (no_alloc).
//!
//! A channel moves a complete WPDU between the physical medium and the [`Session`] buffers.
//! Uses native `async fn in trait` (no `async-trait` crate, no
//! `alloc`) — static dispatch via generics.

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
use cosempdu::error::Error;

/// Asynchronous communication channel: reads/writes a full WPDU (with framing).
///
/// `Frame` — metadata of the received frame (e.g. `Wrapper` for TCP/BLE;
/// for a future HDLC channel — its own frame type). This is the HDLC generalization point.
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
#[allow(async_fn_in_trait)]
pub trait Channel {
    /// Metadata of the received frame (header, payload length).
    type Frame;

    /// Read one WPDU: the header into frame metadata, the APDU into `buf`.
    async fn read(&mut self, buf: &mut [u8]) -> Result<Self::Frame, Error>;

    /// Write `data` (WPDU) to the medium.
    async fn write(&mut self, data: &[u8]) -> Result<(), Error>;
}

/// Asynchronous connection acceptor (e.g. a TCP listener).
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
#[allow(async_fn_in_trait)]
pub trait Listener {
    type Channel: Channel;

    /// Accept one incoming connection and return its channel.
    async fn accept(&mut self) -> Result<Self::Channel, Error>;
}
