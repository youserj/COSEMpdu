//! DLMS/COSEM transport channels (no_alloc).
//!
//! Physical channels are enabled by the Cargo features `optical`, `tcp`, `ble`.
//! Each channel has its own slot pool with independent state.

#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::buffer::{ByteBuffer, Error as BufferError, Reader};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::error::{Error, Result};

/// Maximum xDLMS APDU size (without the transport header).
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub const MAX_APDU: usize = 1024;

/// Headroom for the transport header on top of `MAX_APDU`.
///
/// COSEM Wrapper: version(2) + source wPort(2) + destination wPort(2) +
/// length(2) = 8 bytes; HDLC adds address/control/FCS.
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub const TRANSPORT_OVERHEAD: usize = 8;

/// COSEM Wrapper header version (always 1).
#[cfg(any(feature = "tcp", feature = "ble"))]
pub const WRAPPER_VERSION: u16 = 1;

/// COSEM Wrapper header size (version + source + destination + length).
#[cfg(any(feature = "tcp", feature = "ble"))]
pub const WPDU_HEADER_LEN: usize = 8;

/// Physical medium the connection arrives on.
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

/// Settings of the current connection (2 kinds: HDLC and Wrapper).
///
/// Unlike a plain slot index, it stores the channel state/settings
/// right in the session: for Wrapper — the agreed [`Wrapper`] (ports), for
/// the optical port — [`HdlcState`] (HDLC counters).
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportRef {
    #[cfg(feature = "optical")]
    Hdlc(HdlcState),
    #[cfg(any(feature = "tcp", feature = "ble"))]
    Wrapper(Wrapper),
}

// ---------------------------------------------------------------------------
// COSEM Wrapper (TCP/BLE): connection settings + WPDU header codec
// ---------------------------------------------------------------------------

/// COSEM Wrapper (TCP/BLE): connection settings + WPDU header codec.
///
/// Stores the ports (own → client) and the APDU length read from the header on
/// [`Wrapper::get`]. The APDU is carried separately as the payload.
#[cfg(any(feature = "tcp", feature = "ble"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wrapper {
    source_port: u16,      // server's own wPort (fixed)
    destination_port: u16, // client wPort (changes per connection)
    apdu_len: u16,         // length from the WPDU header (filled in `get`)
}

#[cfg(any(feature = "tcp", feature = "ble"))]
impl Wrapper {
    pub const fn new(source_port: u16, destination_port: u16) -> Self {
        Self {
            source_port,
            destination_port,
            apdu_len: 0,
        }
    }

    /// The server's own wPort (fixed for all connections).
    pub fn source_port(&self) -> u16 {
        self.source_port
    }

    /// The client wPort (changes per connection).
    pub fn destination_port(&self) -> u16 {
        self.destination_port
    }

    /// APDU length from the WPDU header (filled in `get`).
    pub fn apdu_len(&self) -> u16 {
        self.apdu_len
    }

    /// 8-byte WPDU header (version + source + destination + APDU length).
    pub fn header_bytes(&self, apdu_len: u16) -> [u8; 8] {
        let mut h = [0u8; 8];
        h[0..2].copy_from_slice(&WRAPPER_VERSION.to_be_bytes());
        h[2..4].copy_from_slice(&self.source_port().to_be_bytes());
        h[4..6].copy_from_slice(&self.destination_port().to_be_bytes());
        h[6..8].copy_from_slice(&apdu_len.to_be_bytes());
        h
    }

    /// Build the whole WPDU: header + payload via `write_apdu`.
    ///
    /// Writes version/ports with a length placeholder, calls `write_apdu` to write
    /// the APDU (returns its length), patches the length into the header and returns
    /// the total WPDU size.
    pub fn put<E, F>(
        &self,
        buf: &mut ByteBuffer<'_>,
        write_apdu: F,
    ) -> core::result::Result<usize, E>
    where
        F: FnOnce(&mut ByteBuffer<'_>) -> core::result::Result<usize, E>,
        E: From<BufferError>,
    {
        let start = buf.pos();
        buf.put_u16(WRAPPER_VERSION)?;
        buf.put_u16(self.source_port())?;
        buf.put_u16(self.destination_port())?;
        let len_pos = buf.pos();
        buf.put_u16(0)?;

        let apdu_len = write_apdu(buf)?;

        buf.write_at(&(apdu_len as u16).to_be_bytes(), len_pos)?;
        Ok(buf.pos() - start)
    }

    /// Decode the WPDU header; the APDU length lands in `Self::apdu_len`.
    pub fn get(reader: &mut Reader<'_>) -> Result<Self> {
        if reader.get_u16()? != WRAPPER_VERSION {
            return Err(Error::Message("unsupported Wrapper version"));
        }
        let source_port = reader.get_u16()?;
        let destination_port = reader.get_u16()?;
        let apdu_len = reader.get_u16()?;
        Ok(Self {
            source_port,
            destination_port,
            apdu_len,
        })
    }
}

// ---------------------------------------------------------------------------
// HDLC (optical port)
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
        Self {
            send_seq: 0,
            recv_seq: 0,
            window: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Pools (only for enabled features)
// ---------------------------------------------------------------------------

/// HDLC slots-in-use counter (channel state lives in `TransportRef::Hdlc`).
///
/// `N` is the slot limit (matches the number of sessions `Server::<N>`).
#[cfg(feature = "optical")]
pub struct HdlcPool<const N: usize> {
    used: usize,
}

#[cfg(feature = "optical")]
impl<const N: usize> HdlcPool<N> {
    pub const fn new() -> Self {
        Self { used: 0 }
    }

    /// Occupy a slot; `None` if the limit `N` is reached.
    pub fn alloc(&mut self) -> Option<()> {
        if self.used < N {
            self.used += 1;
            Some(())
        } else {
            None
        }
    }

    /// Release a slot.
    pub fn free(&mut self) {
        if self.used > 0 {
            self.used -= 1;
        }
    }
}

/// Wrapper slots-in-use counter (TCP/BLE). Connection settings are stored in
/// `TransportRef::Wrapper`; here — the limit and the server's own wPort.
#[cfg(any(feature = "tcp", feature = "ble"))]
pub struct WrapperPool<const N: usize> {
    source_port: u16,
    used: usize,
}

#[cfg(any(feature = "tcp", feature = "ble"))]
impl<const N: usize> WrapperPool<N> {
    pub const fn new(source_port: u16) -> Self {
        Self {
            source_port,
            used: 0,
        }
    }

    /// The server's own wPort (fixed for all channel connections).
    pub fn source_port(&self) -> u16 {
        self.source_port
    }

    /// Override the server's own wPort (before accepting connections).
    pub fn set_source_port(&mut self, port: u16) {
        self.source_port = port;
    }

    /// Occupy a slot; `None` if the limit `N` is reached.
    pub fn alloc(&mut self) -> Option<()> {
        if self.used < N {
            self.used += 1;
            Some(())
        } else {
            None
        }
    }

    /// Release a slot.
    pub fn free(&mut self) {
        if self.used > 0 {
            self.used -= 1;
        }
    }
}
