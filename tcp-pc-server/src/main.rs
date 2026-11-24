//! Desktop DLMS/COSEM server over TCP (COSEM Wrapper + ACSE + xDLMS).
//!
//! Accepts TCP connections (default `127.0.0.1:4059`), concurrently
//! serves each via `tokio::spawn`: association (`AARQ` → `AARE`),
//! then a loop processing xDLMS requests (GET) until close/timeout.
//!
//! Each connection owns its own `Session` (buffers `rx`/`tx`), so
//! read/process/write proceed without holding the `Server` mutex over network I/O —
//! the mutex is taken only for the short parse/encode phase.

use anyhow::{anyhow, Result};
#[cfg(test)]
use cosempdu::apdu::Conformance;
use cosempdu::buffer::Reader;
use cosempdu::data::Codec;
use cosempdu::error::Error as CosemError;
use dlms1::common_data_types::{DoubleLongUnsigned, OctetString, Unsigned};
use dlms1::ic::{
    AttributeAccessMode, AttributeKey, Clock, DataObject, InterfaceClass, Register, ScalUnit,
};
use dlms1::obis::ObisCode;
use server::{
    Access, AttrDesc, AttrKind, AttrSpec, Channel, Listener, Media, Server, Session, SessionState,
    Wrapper,
};
use static_cell::StaticCell;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Idle read timeout for a connection.
///
/// Must be safely longer than the client's keep-alive interval: closing the
/// socket on idle makes the next keep-alive/GET race with the timeout and the
/// client sees a timeout instead of a response (a 2-minute keep-alive with a
/// 2-minute server timeout reproduces this). Override with
/// `TCP_READ_TIMEOUT_SECS`.
const READ_TIMEOUT_SECS: u64 = 300;

/// Listen address/port (standard DLMS/COSEM-over-TCP port 4059).
const BIND_ADDR: &str = "127.0.0.1:4059";

/// Number of concurrent DLMS sessions (compile-time; transport pools follow this `N`).
const MAX_SESSIONS: usize = 3;

/// Application objects (on top of the default `server::OBJECTS` catalog).
static DATA_OBJ: DataObject = DataObject::new(ObisCode::new(0, 0, 96, 1, 0, 255));
static DATA_OBJ2: DataObject = DataObject::new(ObisCode::new(0, 0, 96, 1, 1, 255));
static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
static CLOCK_OBJ: Clock = Clock::new(ObisCode::CLOCK);

/// Application `(object, OBIS)` pairs — compile-time input for `server::merge_objects`.
const APP_OBJECTS: [(&dyn InterfaceClass, ObisCode); 4] =
    server::objects![DATA_OBJ, DATA_OBJ2, REG_OBJ, CLOCK_OBJ];

/// Full catalog: default (`server::OBJECTS`) + application objects,
/// sorted by OBIS (compile-time).
static OBJECTS: &[&dyn InterfaceClass] =
    &server::merge_objects::<10>(server::OBJECTS, &APP_OBJECTS);

/// Register `value` attribute (read-only, 100).
static DATA_VALUE2: OctetString<10> = OctetString::new(b"hello");
static DATA_VALUE: StaticCell<Unsigned> = StaticCell::new();
static REG_SU: ScalUnit = ScalUnit::new(3, 10);
static REG_VALUE: DoubleLongUnsigned = DoubleLongUnsigned(100);

/// Application attributes (on top of the default `server::ATTRS`; any order —
/// sorting is done in `server::merge_attrs`). OBIS is taken from the object.
static APP_ATTRS: &[AttrSpec] = &[
    AttrSpec {
        key: AttributeKey::new(DATA_OBJ.obis, 2),
        access: Access {
            public: AttributeAccessMode::ReadOnly,
            reader: AttributeAccessMode::NoAccess,
            configurator: AttributeAccessMode::WriteOnly,
        },
        kind: AttrKind::Persistent(5),
    },
    AttrSpec {
        key: AttributeKey::new(DATA_OBJ2.obis, 2),
        access: Access {
            public: AttributeAccessMode::ReadOnly,
            reader: AttributeAccessMode::NoAccess,
            configurator: AttributeAccessMode::WriteOnly,
        },
        kind: AttrKind::Static(&DATA_VALUE2),
    },
    AttrSpec {
        key: AttributeKey::new(REG_OBJ.obis, 2),
        access: Access {
            public: AttributeAccessMode::ReadOnly,
            reader: AttributeAccessMode::NoAccess,
            configurator: AttributeAccessMode::WriteOnly,
        },
        kind: AttrKind::Static(&REG_VALUE),
    },
    AttrSpec {
        key: AttributeKey::new(REG_OBJ.obis, 3),
        access: Access {
            public: AttributeAccessMode::ReadOnly,
            reader: AttributeAccessMode::NoAccess,
            configurator: AttributeAccessMode::WriteOnly,
        },
        kind: AttrKind::Static(&REG_SU),
    },
];

/// Full registry: default (`server::ATTRS`) + application attributes; OBIS is resolved
/// to the object index, sorted by key (compile-time).
static ATTRS: &[AttrDesc] =
    &server::merge_attrs::<32>(server::OBJECTS, &APP_OBJECTS, server::ATTRS, APP_ATTRS);

/// ROM codec array for Static attributes (in `server::ATTRS` + `APP_ATTRS` order).
static CODECS: &[&dyn Codec] = &server::merge_codecs::<11>(server::ATTRS, APP_ATTRS);

/// Method registry resolved against the merged object catalog.
static METHODS: [server::MethodDesc; 2] =
    server::merge_methods::<2>(server::OBJECTS, &APP_OBJECTS, server::METHODS, &[]);

static mut MUT: [Option<&'static mut dyn Codec>; 6] = [None, None, None, None, None, None];

/// TCP channel over tokio: reads/writes a complete WPDU (Wrapper framing).
///
/// Reads are wrapped in a timeout (`read_timeout`, default 120 s): while idle
/// the read fails, and the caller resets the session to Idle.
pub struct TcpChannel {
    stream: TcpStream,
    read_timeout: Duration,
}

impl TcpChannel {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            read_timeout: Duration::from_secs(READ_TIMEOUT_SECS),
        }
    }

    /// Override the read timeout (default 120 s).
    pub fn set_read_timeout(&mut self, timeout: Duration) {
        self.read_timeout = timeout;
    }

    /// Read exactly `buf.len()` bytes with the read timeout.
    async fn read_exact_timeout(&mut self, buf: &mut [u8]) -> Result<(), CosemError> {
        tokio::time::timeout(self.read_timeout, self.stream.read_exact(buf))
            .await
            .map_err(|_| CosemError::Message("tcp read timeout"))?
            .map_err(|_| CosemError::Message("tcp read failed"))?;
        Ok(())
    }
}

impl Channel for TcpChannel {
    type Frame = Wrapper;

    async fn read(&mut self, buf: &mut [u8]) -> Result<Wrapper, CosemError> {
        // Wrapper header (8 bytes) goes straight into buf; the APDU overwrites it afterwards.
        if buf.len() < 8 {
            return Err(CosemError::ByteBufferError(
                cosempdu::buffer::Error::NotEnoughSpace { needed: 8 },
            ));
        }
        self.read_exact_timeout(&mut buf[..8]).await?;

        // Parse the header to learn the APDU length.
        let setting = Wrapper::get(&mut Reader::new(&buf[..8]))?;
        let apdu_len = setting.apdu_len() as usize;
        if apdu_len > buf.len() {
            return Err(CosemError::ByteBufferError(
                cosempdu::buffer::Error::NotEnoughSpace { needed: apdu_len },
            ));
        }

        // APDU goes to the start of buf (overwriting the header).
        self.read_exact_timeout(&mut buf[..apdu_len]).await?;
        Ok(setting)
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), CosemError> {
        self.stream
            .write_all(data)
            .await
            .map_err(|_| CosemError::Message("tcp write failed"))
    }
}

/// TCP acceptor over tokio (implements [`Listener`]).
pub struct TcpListener {
    inner: tokio::net::TcpListener,
}

impl Listener for TcpListener {
    type Channel = TcpChannel;

    async fn accept(&mut self) -> Result<TcpChannel, CosemError> {
        let (stream, _) = self
            .inner
            .accept()
            .await
            .map_err(|_| CosemError::Message("tcp accept failed"))?;
        Ok(TcpChannel::new(stream))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let data_value = DATA_VALUE.init(Unsigned(1));
    unsafe {
        // Default slots (LDN + server-system-title + LLS secrets) are initialized by the server.
        server::init_mutable_defaults(&mut *core::ptr::addr_of_mut!(MUT));
        MUT[5] = Some(data_value);
    }

    let mut server: Server<MAX_SESSIONS> =
        Server::<MAX_SESSIONS>::with_capacity(OBJECTS, ATTRS, CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        })
        .with_methods(&METHODS);
    server.set_wport(1);
    let server = Arc::new(Mutex::new(server));

    let read_timeout = Duration::from_secs(
        std::env::var("TCP_READ_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(READ_TIMEOUT_SECS),
    );
    let mut listener = TcpListener {
        inner: tokio::net::TcpListener::bind(BIND_ADDR).await?,
    };
    println!("tcp-pc-server: listening on {BIND_ADDR}");

    loop {
        let mut channel = listener
            .accept()
            .await
            .map_err(|e| anyhow!("accept: {e:?}"))?;
        channel.set_read_timeout(read_timeout);
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(server, channel).await {
                eprintln!("connection failed: {e:#}");
            }
        });
    }
}

/// Serve one connection: a request loop (AARQ/AARE, GET/SET, RLRQ) until
/// close/timeout.
async fn handle_connection(
    server: Arc<Mutex<Server<MAX_SESSIONS>>>,
    mut channel: TcpChannel,
) -> Result<()> {
    // The session (with rx/tx buffers) belongs to this connection task.
    let mut session = server.lock().await.on_connect(Media::Tcp)?;

    // xDLMS request loop (AARQ/AARE, GET/SET, RLRQ); exit on
    // RLRQ (state = Disconnecting)/timeout/close/error.
    let result = loop {
        if let Err(e) = request_session(&server, &mut session, &mut channel).await {
            break Err(e);
        }
        if session.settings.state == SessionState::Disconnecting {
            break Ok(());
        }
    };

    // Always release the transport slot.
    server.lock().await.on_disconnect(session.media());
    result
}

/// Handle one xDLMS request (AARQ/GET/SET/RLRQ): read into session.rx (without
/// the mutex) → process (short mutex, no I/O) → write from session.tx (without
/// the mutex). Association release is reflected in `session.settings.state`.
async fn request_session(
    server: &Arc<Mutex<Server<MAX_SESSIONS>>>,
    session: &mut Session,
    channel: &mut TcpChannel,
) -> Result<()> {
    let received = channel
        .read(session.rx_mut())
        .await
        .map_err(|e| anyhow!("read: {e:?}"))?;
    session.set_rx_len(received.apdu_len() as usize);

    let send = {
        let mut srv = server.lock().await;
        let (settings, transport_ref, rx, tx) = session.parts();
        srv.process_request(settings, transport_ref, rx, tx, received)
            .map_err(|e| anyhow!("request: {e:?}"))?
    };

    if send {
        channel
            .write(session.tx())
            .await
            .map_err(|e| anyhow!("write: {e:?}"))?;
    }
    session.clear_rx();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosempdu::acse::{
        AARQapdu, ACSEApdu, AcseServiceUser, ApplicationContextName, AssociateSourceDiagnostic,
        AssociationResult,
    };
    use cosempdu::apdu::InitiateRequest;
    use cosempdu::apdu::{
        CosemAttributeDescriptor, GetDataResult, GetRequest, GetResponse, GetResponseNormal,
        ImplicitTagged, InvokeIdAndPriority,
    };
    use cosempdu::buffer::ByteBuffer;

    static mut NO_MUT: [Option<&'static mut dyn Codec>; 0] = [];
    static REG_SPEC: &[AttrSpec] = &[AttrSpec {
        key: AttributeKey::new(REG_OBJ.obis, 2),
        access: Access {
            public: AttributeAccessMode::ReadOnly,
            reader: AttributeAccessMode::NoAccess,
            configurator: AttributeAccessMode::WriteOnly,
        },
        kind: AttrKind::Static(&REG_VALUE),
    }];
    static REG_ATTRS: [AttrDesc; 29] =
        server::merge_attrs::<29>(server::OBJECTS, &APP_OBJECTS, server::ATTRS, REG_SPEC);
    static REG_CODECS: [&dyn Codec; 9] = server::merge_codecs::<9>(server::ATTRS, REG_SPEC);

    /// Real AARQ WPDU from a DLMS client (LN without ciphering): version 1, src=16,
    /// dst=1 (server Wrapper port), APDU length 31. The InitiateRequest tail
    /// `1E 5D FF FF` (vaa-name) is ignored by the project when parsing.
    const AARQ_WPDU: &[u8] = &[
        0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x1F, 0x60, 0x1D, 0xA1, 0x09, 0x06, 0x07, 0x60,
        0x85, 0x74, 0x05, 0x08, 0x01, 0x01, 0xBE, 0x10, 0x04, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x06,
        0x5F, 0x1F, 0x04, 0x00, 0x62, 0x1E, 0x5D, 0xFF, 0xFF,
    ];

    /// Build a WPDU with an AARQ (client association request) without
    /// authentication, from `source_sap`.
    fn make_aarq_wpdu_from(source_sap: u16) -> Vec<u8> {
        let req = InitiateRequest::new(Conformance([0x00, 0x7E, 0x1F]), 1200);
        let mut ui = [0u8; 64];
        let n = req.put(&mut ByteBuffer::new(&mut ui)).unwrap();

        let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        aarq.user_information = Some(&ui[..n]);
        let mut aarq_bytes = [0u8; 256];
        let m = aarq.put(&mut ByteBuffer::new(&mut aarq_bytes)).unwrap();

        // destination_port = server's Wrapper port (1).
        let setting = Wrapper::new(source_sap, 1);
        let mut wpdu = vec![0u8; 8 + m];
        let mut buf = ByteBuffer::new(&mut wpdu);
        setting
            .put(&mut buf, |b| b.write(&aarq_bytes[..m]))
            .unwrap();
        wpdu
    }

    /// Anonymous public association (client source_port = 0x10).
    fn make_aarq_wpdu() -> Vec<u8> {
        make_aarq_wpdu_from(0x10)
    }

    /// Build a WPDU with a Get-Request (read register `REG_OBJ` `value`, attr 2).
    fn make_get_wpdu() -> Vec<u8> {
        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: REG_OBJ.class_id().as_u16(),
            instance_id: REG_OBJ.obis().bytes,
            attribute_id: 2,
        };
        let mut apdu = [0u8; 64];
        let n = GetRequest::put_normal(invoke, descriptor, None, &mut ByteBuffer::new(&mut apdu))
            .unwrap();

        // Client: source_port = 16, destination_port = 1 (server port).
        let setting = Wrapper::new(16, 1);
        let mut wpdu = vec![0u8; 8 + n];
        let mut buf = ByteBuffer::new(&mut wpdu);
        setting.put(&mut buf, |b| b.write(&apdu[..n])).unwrap();
        wpdu
    }

    #[tokio::test]
    async fn tcp_handshake_end_to_end() {
        let mut server: Server<MAX_SESSIONS> =
            Server::<MAX_SESSIONS>::with_capacity(OBJECTS, &ATTRS, &CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let server = Arc::new(Mutex::new(server));

        let mut listener = TcpListener {
            inner: tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        };
        let addr = listener.inner.local_addr().unwrap();
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let channel = listener.accept().await.unwrap();
            handle_connection(srv, channel).await.unwrap();
        });

        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket.write_all(AARQ_WPDU).await.unwrap();

        let mut header = [0u8; 8];
        socket.read_exact(&mut header).await.unwrap();
        let setting = Wrapper::get(&mut Reader::new(&header)).unwrap();
        let mut apdu = vec![0u8; setting.apdu_len() as usize];
        socket.read_exact(&mut apdu).await.unwrap();

        let acse = ACSEApdu::get(&mut Reader::new(&apdu)).unwrap();
        match acse {
            ACSEApdu::Aare(a) => assert_eq!(a.result, AssociationResult::Accepted),
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// Full cycle: AARQ → AARE, then Get-Request → Get-Response.
    #[tokio::test]
    async fn tcp_get_end_to_end() {
        let mut server: Server<MAX_SESSIONS> =
            Server::<MAX_SESSIONS>::with_capacity(OBJECTS, &REG_ATTRS, &REG_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let server = Arc::new(Mutex::new(server));

        let mut listener = TcpListener {
            inner: tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        };
        let addr = listener.inner.local_addr().unwrap();
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let channel = listener.accept().await.unwrap();
            handle_connection(srv, channel).await.unwrap();
        });

        let mut socket = TcpStream::connect(addr).await.unwrap();

        // 1) Association: AARQ → AARE.
        let wpdu = make_aarq_wpdu();
        socket.write_all(&wpdu).await.unwrap();
        let mut header = [0u8; 8];
        socket.read_exact(&mut header).await.unwrap();
        let setting = Wrapper::get(&mut Reader::new(&header)).unwrap();
        let mut aare = vec![0u8; setting.apdu_len() as usize];
        socket.read_exact(&mut aare).await.unwrap();
        let acse = ACSEApdu::get(&mut Reader::new(&aare)).unwrap();
        match acse {
            ACSEApdu::Aare(a) => assert_eq!(a.result, AssociationResult::Accepted),
            other => panic!("expected AARE, got {other:?}"),
        }

        // 2) GET: Get-Request → Get-Response (value = DoubleLongUnsigned(100)).
        let get_wpdu = make_get_wpdu();
        socket.write_all(&get_wpdu).await.unwrap();
        let mut header = [0u8; 8];
        socket.read_exact(&mut header).await.unwrap();
        let setting = Wrapper::get(&mut Reader::new(&header)).unwrap();
        let mut resp = vec![0u8; setting.apdu_len() as usize];
        socket.read_exact(&mut resp).await.unwrap();

        let response = {
            let mut r = Reader::new(&resp);
            GetResponse::get(&mut r).unwrap()
        };
        match response {
            GetResponse::Normal(GetResponseNormal {
                invoke,
                result: GetDataResult::Data(r),
            }) => {
                assert_eq!(invoke.invoke_id(), 1);
                // DoubleLongUnsigned(100) = [0x06, 0x00, 0x00, 0x00, 0x64].
                assert_eq!(r.as_bytes(), &[0x06, 0x00, 0x00, 0x00, 0x64]);
            }
            _ => panic!("expected GetResponse::Normal with data"),
        }
    }

    /// Full cycle: AARQ → AARE, then Get-Request attr 1 (`logical_name`) for
    /// the base association `0.0.40.0.0.255`.
    #[tokio::test]
    async fn tcp_get_logical_name_base_association() {
        let mut server: Server<MAX_SESSIONS> =
            Server::<MAX_SESSIONS>::with_capacity(OBJECTS, &REG_ATTRS, &REG_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let server = Arc::new(Mutex::new(server));

        let mut listener = TcpListener {
            inner: tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        };
        let addr = listener.inner.local_addr().unwrap();
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let channel = listener.accept().await.unwrap();
            handle_connection(srv, channel).await.unwrap();
        });

        let mut socket = TcpStream::connect(addr).await.unwrap();

        // AARQ → AARE
        socket.write_all(&make_aarq_wpdu()).await.unwrap();
        let mut header = [0u8; 8];
        socket.read_exact(&mut header).await.unwrap();
        let setting = Wrapper::get(&mut Reader::new(&header)).unwrap();
        let mut aare = vec![0u8; setting.apdu_len() as usize];
        socket.read_exact(&mut aare).await.unwrap();

        // GET attr 1 of 0.0.40.0.0.255
        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: dlms1::ic::ClassId::AssociationLn.as_u16(),
            instance_id: server::ASSOC_LN_BASE_OBIS.bytes,
            attribute_id: 1,
        };
        let mut apdu = [0u8; 64];
        let n = GetRequest::put_normal(invoke, descriptor, None, &mut ByteBuffer::new(&mut apdu))
            .unwrap();
        let mut wpdu = vec![0u8; 8 + n];
        {
            let mut b = ByteBuffer::new(&mut wpdu);
            Wrapper::new(16, 1)
                .put(&mut b, |b| b.write(&apdu[..n]))
                .unwrap();
        }
        socket.write_all(&wpdu).await.unwrap();

        let resp = tokio::time::timeout(Duration::from_secs(3), async {
            let mut header = [0u8; 8];
            socket.read_exact(&mut header).await.unwrap();
            let setting = Wrapper::get(&mut Reader::new(&header)).unwrap();
            let mut resp = vec![0u8; setting.apdu_len() as usize];
            socket.read_exact(&mut resp).await.unwrap();
            resp
        })
        .await
        .expect("GET response timeout");

        let response = {
            let mut r = Reader::new(&resp);
            GetResponse::get(&mut r).unwrap()
        };
        match response {
            GetResponse::Normal(GetResponseNormal {
                result: GetDataResult::Data(r),
                ..
            }) => {
                assert_eq!(r.as_bytes(), &[0x09, 0x06, 0, 0, 40, 0, 0, 255]);
            }
            other => panic!("expected GetResponse::Normal with data, got {other:?}"),
        }
    }

    /// A reader association (SAP 0x20) without an authentication mechanism is
    /// rejected: the reader requires LLS (`authentication_mechanism_name`, attr 6).
    #[tokio::test]
    async fn tcp_rejects_reader_aarq_without_mechanism() {
        let mut server: Server<MAX_SESSIONS> =
            Server::<MAX_SESSIONS>::with_capacity(OBJECTS, &ATTRS, &CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let server = Arc::new(Mutex::new(server));

        let mut listener = TcpListener {
            inner: tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        };
        let addr = listener.inner.local_addr().unwrap();
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let channel = listener.accept().await.unwrap();
            handle_connection(srv, channel).await.unwrap();
        });

        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket.write_all(&make_aarq_wpdu_from(0x20)).await.unwrap();

        let mut header = [0u8; 8];
        socket.read_exact(&mut header).await.unwrap();
        let setting = Wrapper::get(&mut Reader::new(&header)).unwrap();
        let mut apdu = vec![0u8; setting.apdu_len() as usize];
        socket.read_exact(&mut apdu).await.unwrap();

        match ACSEApdu::get(&mut Reader::new(&apdu)).unwrap() {
            ACSEApdu::Aare(a) => {
                assert_eq!(a.result, AssociationResult::RejectedPermanent);
                assert_eq!(
                    a.result_source_diagnostic,
                    AssociateSourceDiagnostic::ServiceUser(
                        AcseServiceUser::AuthenticationMechanismNameRequired
                    )
                );
            }
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// Client: connects, sends an LLS AARQ and checks it received AARE (accepted).
    async fn run_client(addr: std::net::SocketAddr) {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket.write_all(&make_aarq_wpdu()).await.unwrap();

        let mut header = [0u8; 8];
        socket.read_exact(&mut header).await.unwrap();
        let setting = Wrapper::get(&mut Reader::new(&header)).unwrap();
        let mut apdu = vec![0u8; setting.apdu_len() as usize];
        socket.read_exact(&mut apdu).await.unwrap();

        let acse = ACSEApdu::get(&mut Reader::new(&apdu)).unwrap();
        match acse {
            ACSEApdu::Aare(a) => assert_eq!(a.result, AssociationResult::Accepted),
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// Two clients associate with the server concurrently (2 of MAX_SESSIONS sessions).
    #[tokio::test]
    async fn two_concurrent_clients() {
        let mut server: Server<MAX_SESSIONS> =
            Server::<MAX_SESSIONS>::with_capacity(OBJECTS, &ATTRS, &CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let server = Arc::new(Mutex::new(server));

        let mut listener = TcpListener {
            inner: tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        };
        let addr = listener.inner.local_addr().unwrap();

        // accept loop for 2 connections.
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            for _ in 0..2 {
                let channel = listener.accept().await.unwrap();
                let s = Arc::clone(&srv);
                tokio::spawn(handle_connection(s, channel));
            }
        });

        // Two clients send AARQ concurrently and wait for AARE.
        tokio::join!(run_client(addr), run_client(addr));
    }
}
