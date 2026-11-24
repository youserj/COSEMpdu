//! DLMS/COSEM session — shared by all transport channels.
//!
//! `Session` (with `rx`/`tx` buffers) belongs to the **caller** (the connection
//! task or [`Server::serve`]), not to `Server`: the server holds only the registry,
//! catalog and slot counters, while the exchange buffers live in the session.
//!
//! Association parameters are factored out into [`Settings`] so they can be
//! borrowed independently of `rx`/`tx` (e.g. `&Settings` + `&mut rx`
//! on receive and `&Settings` + `&mut tx` on reply).

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
use crate::transport::{Media, TransportRef, MAX_APDU, TRANSPORT_OVERHEAD};
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
use crate::Error;
use cosempdu::acse::{ApplicationContextName, SystemTitle};
use cosempdu::apdu::{Conformance, CosemAttributeDescriptor};
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
use cosempdu::buffer::{ArrayBuffer, ByteBuffer, Reader};
use dlms1::ic::client_sap;

/// Session exchange buffer size (APDU + transport header).
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub const RX_BUF: usize = MAX_APDU + TRANSPORT_OVERHEAD;

/// DLMS/COSEM association states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Associating,
    Associated,
    Disconnecting,
}

/// State of an in-progress `get-response-with-datablock` transfer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetBlock {
    /// Descriptor of the attribute being read.
    pub descriptor: CosemAttributeDescriptor,
    /// Block number expected in the next `Get-Request-Next`.
    pub next_block: u32,
}

/// Dedicated key (size encoded by the variant: 16 or 32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedicatedKey {
    /// No key (no ciphering or not provided).
    None,
    /// AES-128 → 16 bytes (security_suite 0/1).
    #[cfg(feature = "aes128")]
    Aes128([u8; 16]),
    /// AES-256 → 32 bytes (security_suite 2).
    #[cfg(feature = "aes256")]
    Aes256([u8; 32]),
}

impl DedicatedKey {
    /// Build a key from the slice length (16 → `Aes128`, 32 → `Aes256`, else `None`).
    pub fn from_slice(key: &[u8]) -> Self {
        match key.len() {
            #[cfg(feature = "aes128")]
            16 => {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(key);
                DedicatedKey::Aes128(buf)
            }
            #[cfg(feature = "aes256")]
            32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(key);
                DedicatedKey::Aes256(buf)
            }
            _ => DedicatedKey::None,
        }
    }
}

/// Client calling-AE-qualifier — the ECDSA public key for HLS signing.
///
/// Like `DedicatedKey`, stored by value (`None` variant = qualifier
/// absent), but not in the session's persistent RAM: it lives only during the handshake
/// (shared scratch in `lib.rs`); reset to `None` after the signature check.
#[cfg(any(feature = "ecdsa_p256", feature = "ecdsa_p384"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingAeQualifier {
    /// No qualifier.
    None,
    /// ECDSA P-256: 64-byte public key (x || y).
    #[cfg(feature = "ecdsa_p256")]
    P256([u8; 64]),
    /// ECDSA P-384: 96-byte public key (x || y).
    #[cfg(feature = "ecdsa_p384")]
    P384([u8; 96]),
}

#[cfg(any(feature = "ecdsa_p256", feature = "ecdsa_p384"))]
impl CallingAeQualifier {
    /// Build from the slice length (64 → `P256`, 96 → `P384`, else `None`).
    pub fn from_slice(key: &[u8]) -> Self {
        match key.len() {
            #[cfg(feature = "ecdsa_p256")]
            64 => {
                let mut buf = [0u8; 64];
                buf.copy_from_slice(key);
                CallingAeQualifier::P256(buf)
            }
            #[cfg(feature = "ecdsa_p384")]
            96 => {
                let mut buf = [0u8; 96];
                buf.copy_from_slice(key);
                CallingAeQualifier::P384(buf)
            }
            _ => CallingAeQualifier::None,
        }
    }
}

/// DLMS association settings/state (independent of the `rx`/`tx` buffers).
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// Negotiated conformance (result of AARQ/AARE).
    pub conformance: Conformance,
    /// Index of the current Association LN association in the object catalog
    /// (`AttrKey.object`); `u8::MAX` means no association selected.
    pub assoc_idx: u8,
    /// Client client_SAP (0x10 public / 0x20 reader / 0x30 configurator). TODO: make without this field, only assoc_idx
    pub client_sap: u8,
    /// Authentication chosen by the client (sender-acse-requirements, bit 0).
    pub authenticated: bool,
    /// Negotiated application-context-name (result of AARQ/AARE).
    pub app_context: ApplicationContextName,
    /// Client system-title (calling-AP-title from AARQ); `None` if not provided.
    pub system_title_c: Option<SystemTitle>,
    /// Dedicated key (for ciphering; length depends on the SecuritySetup security_suite attribute).
    pub dedicated_key: DedicatedKey,
    /// Maximum PDU size that can be sent to the client
    /// (min(MAX_APDU, client_max_receive_pdu_size); for GBT slicing).
    pub tx_max: u16,
    /// In-progress `get-response-with-datablock` transfer (`Get-Request-Next`).
    pub get_block: Option<GetBlock>,
    /// Association state.
    pub state: SessionState,
}

impl Settings {
    pub const fn new() -> Self {
        Self::with_sap(0)
    }

    /// Access-context settings based only on `client_sap`
    /// (no authentication/ciphering/signing); `assoc_idx` stays `u8::MAX`.
    pub const fn with_sap(client_sap: u8) -> Self {
        Self {
            conformance: Conformance([0; 3]),
            assoc_idx: u8::MAX,
            client_sap,
            authenticated: false,
            app_context: ApplicationContextName::LogicalNameNoCiphering,
            system_title_c: None,
            dedicated_key: DedicatedKey::None,
            tx_max: 0,
            get_block: None,
            state: SessionState::Idle,
        }
    }

    /// Public-client context (SAP 0x10).
    pub const fn public() -> Self {
        Self::with_sap(client_sap::PUBLIC)
    }

    /// Reader-client context (SAP 0x20).
    pub const fn reader() -> Self {
        Self::with_sap(client_sap::READER)
    }

    /// Configurator-client context (SAP 0x30).
    pub const fn configurator() -> Self {
        Self::with_sap(client_sap::CONFIGURATOR)
    }

    /// Whether the association is ciphered (application-context with ciphering).
    pub const fn is_ciphered(&self) -> bool {
        matches!(
            self.app_context,
            ApplicationContextName::LogicalNameCiphering
                | ApplicationContextName::ShortNameCiphering
        )
    }

    /// Whether the request is digitally signed.
    ///
    /// TODO: derive from `security_suite` (SecuritySetup attribute, read after
    /// client_SAP): suites 1/2 support ECDSA, suite 0 does not.
    pub const fn is_digitally_signed(&self) -> bool {
        false
    }
}

/// Session: transport channel + association settings + exchange buffers.
#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub struct Session {
    /// Association settings/state (used together with `rx` or `tx`).
    pub settings: Settings,
    /// Receive buffer.
    pub rx: ArrayBuffer<RX_BUF>,
    /// Transmit buffer.
    pub tx: ArrayBuffer<RX_BUF>,
    /// Transport channel settings/state of the current connection.
    pub transport_ref: TransportRef,
    /// Channel the connection was opened on (for counter release in `release`).
    media: Media,
    /// invoke-id counter.
    invoke_id: u8,
}

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
impl Session {
    pub const fn new(media: Media, transport_ref: TransportRef) -> Self {
        Self {
            settings: Settings::new(),
            rx: ArrayBuffer::new(),
            tx: ArrayBuffer::new(),
            transport_ref,
            media,
            invoke_id: 0,
        }
    }

    pub fn media(&self) -> Media {
        self.media
    }

    pub fn invoke_id(&self) -> u8 {
        self.invoke_id
    }

    /// Split the session into independently borrowable parts:
    /// `(settings, transport_ref, rx, tx)`.
    pub fn parts(
        &mut self,
    ) -> (
        &mut Settings,
        &mut TransportRef,
        &ArrayBuffer<RX_BUF>,
        &mut ArrayBuffer<RX_BUF>,
    ) {
        (
            &mut self.settings,
            &mut self.transport_ref,
            &self.rx,
            &mut self.tx,
        )
    }

    /// Accumulated receive bytes (slice up to the current position).
    pub fn rx(&self) -> &[u8] {
        self.rx.extract()
    }

    /// Length of the accumulated receive data.
    pub fn rx_len(&self) -> usize {
        self.rx.pos()
    }

    /// Transient `Reader` over the received bytes.
    pub fn reader(&self) -> Reader<'_> {
        Reader::new(self.rx.extract())
    }

    /// Full rx buffer for reading from the channel (then `set_rx_len`).
    pub fn rx_mut(&mut self) -> &mut [u8] {
        self.rx.as_bytes_mut()
    }

    /// Set the length of valid receive bytes.
    pub fn set_rx_len(&mut self, len: usize) {
        let _ = self.rx.set_pos(len);
    }

    /// Response bytes (slice up to the current position).
    pub fn tx(&self) -> &[u8] {
        self.tx.extract()
    }

    /// Length of the response bytes.
    pub fn tx_len(&self) -> usize {
        self.tx.pos()
    }

    /// Transient `ByteBuffer` for writing the response (then `set_tx_len`).
    pub fn tx_buffer(&mut self) -> ByteBuffer<'_> {
        ByteBuffer::new(self.tx.as_bytes_mut())
    }

    /// Set the length of valid response bytes.
    pub fn set_tx_len(&mut self, len: usize) {
        let _ = self.tx.set_pos(len);
    }

    /// Encode the response into the tx buffer and record its length.
    ///
    /// Encapsulates the repeated pair `tx_buffer()` → encode → `set_tx_len(n)`.
    pub fn encode_tx<E, F>(&mut self, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut ByteBuffer<'_>) -> Result<usize, E>,
        Error: From<E>,
    {
        let n = f(&mut self.tx_buffer())?;
        self.set_tx_len(n);
        Ok(())
    }

    /// Append bytes to the rx buffer. Returns `false` on overflow.
    pub fn push_rx(&mut self, data: &[u8]) -> bool {
        if self.rx.remaining() < data.len() {
            return false;
        }
        self.rx.write(data).is_ok()
    }

    /// Reset the rx buffer (after processing a frame).
    pub fn clear_rx(&mut self) {
        self.rx.clear();
    }
}
