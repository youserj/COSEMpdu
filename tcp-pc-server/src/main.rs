//! Desktop DLMS/COSEM сервер поверх TCP (COSEM Wrapper + ACSE + xDLMS).
//!
//! Принимает TCP-соединения (по умолчанию `127.0.0.1:4059`), конкурентно
//! обслуживает каждое через `tokio::spawn`: ассоциация (`AARQ` → `AARE`),
//! затем цикл обработки xDLMS-запросов (GET) до закрытия/таймаута.
//!
//! Каждое соединение владеет собственной `Session` (буферы `rx`/`tx`), поэтому
//! read/process/write идут без удержания мьютекса `Server` на сетевом I/O —
//! мьютекс берётся только на короткую фазу разбора/кодирования.

use std::sync::Arc;
use std::time::Duration;
use static_cell::StaticCell;
use anyhow::{anyhow, Result};
use cosempdu::apdu_sn::Conformance;
use cosempdu::buffer::Reader;
use cosempdu::error::Error as CosemError;
use dlms1::common_data_types::{DoubleLongUnsigned, Unsigned, OctetString};
use dlms1::ic::{Clock, DataObject, InterfaceClass, Register, ScalUnit};
use dlms1::obis::ObisCode;
use server::{Access, AccessMask, Channel, Listener, Media, Server, Session, Wrapper};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Адрес/порт прослушивания (стандартный DLMS/COSEM-over-TCP порт 4059).
const BIND_ADDR: &str = "127.0.0.1:4059";

/// Число одновременных DLMS-сессий (compile-time; пулы транспорта следуют этому `N`).
const MAX_SESSIONS: usize = 3;

/// Предлагаемый сервером conformance (LN, без шифрования; базовый набор GET/SET/ACTION).
const SERVER_CONFORMANCE: Conformance = Conformance([0x00, 0x7E, 0x1F]);

/// Каталог COSEM-объектов, доступных серверу (Register + Clock).
static DATA_OBJ: DataObject = DataObject::new(ObisCode::new(0, 0, 96, 1, 0, 255));
static DATA_OBJ2: DataObject = DataObject::new(ObisCode::new(0, 0, 96, 1, 1, 255));
static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
static CLOCK_OBJ: Clock = Clock::new(ObisCode::CLOCK);
static OBJECTS: &[&dyn InterfaceClass] = &[&DATA_OBJ, &DATA_OBJ2, &REG_OBJ, &CLOCK_OBJ];

/// Значение атрибута `value` регистра (read-only, 100).
static DATA_VALUE: StaticCell<Unsigned> = StaticCell::new();
static DATA_VALUE2: OctetString<10> = OctetString::new(b"hello");
static REG_VALUE: DoubleLongUnsigned = DoubleLongUnsigned(100);
static REG_SU: ScalUnit = ScalUnit::new(3, 10);

/// TCP-канал поверх tokio: читает/пишет полный WPDU (Wrapper-фрейминг).
///
/// Чтение обёрнуто в таймаут (`read_timeout`, по умолчанию 120 c): при простое
/// канала чтение завершается ошибкой, и вызывающий сбрасывает сессию в Idle.
pub struct TcpChannel {
    stream: TcpStream,
    read_timeout: Duration,
}

impl TcpChannel {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream, read_timeout: Duration::from_secs(120) }
    }

    /// Переопределить таймаут чтения (по умолчанию 120 c).
    pub fn set_read_timeout(&mut self, timeout: Duration) {
        self.read_timeout = timeout;
    }

    /// Прочитать ровно `buf.len()` байт с таймаутом чтения.
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
        // Wrapper-заголовок (8 байт) — сразу в buf; затем APDU перезапишет его.
        if buf.len() < 8 {
            return Err(CosemError::ByteBufferError(cosempdu::buffer::Error::NotEnoughSpace { needed: 8 }));
        }
        self.read_exact_timeout(&mut buf[..8]).await?;

        // Разбираем заголовок, чтобы узнать длину APDU.
        let setting = Wrapper::get(&mut Reader::new(&buf[..8]))?;
        let apdu_len = setting.apdu_len() as usize;
        if apdu_len > buf.len() {
            return Err(CosemError::ByteBufferError(cosempdu::buffer::Error::NotEnoughSpace { needed: apdu_len }));
        }

        // APDU — в начало buf (перезаписываем заголовок).
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

/// TCP-приёмник поверх tokio (реализует [`Listener`]).
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
    let mut server: Server<'static, MAX_SESSIONS> =
        Server::<'static, MAX_SESSIONS>::with_capacity(OBJECTS, SERVER_CONFORMANCE);
    server.set_wport(1);
    server.add_static(
        REG_OBJ.value(),
        &REG_VALUE,
        Access { read: AccessMask::PUBLIC, write: AccessMask::CONFIGURATOR },
    )?;
    server.add_static(
        REG_OBJ.scaler_unit(),
        &REG_SU,
        Access { read: AccessMask::PUBLIC, write: AccessMask::CONFIGURATOR },
    )?;
    let data_value = DATA_VALUE.init(Unsigned(1));
    server.add_persistent(
        DATA_OBJ.value(),
        data_value,
        Access { read: AccessMask::PUBLIC, write: AccessMask::CONFIGURATOR },
    )?;
    server.add_static(
        DATA_OBJ2.value(),
        &DATA_VALUE2,
        Access { read: AccessMask::PUBLIC, write: AccessMask::CONFIGURATOR },
    )?;
    let server = Arc::new(Mutex::new(server));

    let mut listener = TcpListener {
        inner: tokio::net::TcpListener::bind(BIND_ADDR).await?,
    };
    println!("tcp-pc-server: listening on {BIND_ADDR}");

    loop {
        let channel = listener.accept().await.map_err(|e| anyhow!("accept: {e:?}"))?;
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(server, channel).await {
                eprintln!("connection failed: {e:#}");
            }
        });
    }
}

/// Обслуживание одного соединения: ассоциация → цикл GET-запросов, до закрытия/таймаута.
async fn handle_connection(
    server: Arc<Mutex<Server<'static, MAX_SESSIONS>>>,
    mut channel: TcpChannel,
) -> Result<()> {
    // Сессия (с буферами rx/tx) принадлежит этой задаче соединения.
    let mut session = server.lock().await.on_connect(Media::Tcp)?;

    // Ассоциация (разовый обмен AARQ → AARE).
    if let Err(e) = associate_session(&server, &mut session, &mut channel).await {
        server.lock().await.on_disconnect(session.media());
        return Err(e);
    }

    // Цикл обслуживания xDLMS-запросов; выходим по RLRQ/таймауту/закрытию/ошибке.
    let result = loop {
        match request_session(&server, &mut session, &mut channel).await {
            Ok(true) => {}
            Ok(false) => break Ok(()),
            Err(e) => break Err(e),
        }
    };

    // Всегда освобождаем транспортный слот.
    server.lock().await.on_disconnect(session.media());
    result
}

/// Ассоциация (AARQ → AARE): read в session.rx (без мьютекса) → accept (короткий
/// мьютекс, без I/O) → write из session.tx (без мьютекса).
async fn associate_session(
    server: &Arc<Mutex<Server<'static, MAX_SESSIONS>>>,
    session: &mut Session,
    channel: &mut TcpChannel,
) -> Result<()> {
    let received = channel.read(session.rx_mut()).await.map_err(|e| anyhow!("read: {e:?}"))?;
    session.set_rx_len(received.apdu_len() as usize);

    {
        let srv = server.lock().await;
        srv.accept_association(session, received)
            .map_err(|e| anyhow!("associate: {e:?}"))?;
    }

    channel.write(session.tx()).await.map_err(|e| anyhow!("write: {e:?}"))?;
    session.clear_rx();
    Ok(())
}

/// Обработка одного xDLMS-запроса (GET/RLRQ): read в session.rx (без мьютекса) →
/// process (короткий мьютекс, без I/O) → write из session.tx (без мьютекса).
/// Возвращает `Ok(false)`, если получен RLRQ (ассоциация освобождена).
async fn request_session(
    server: &Arc<Mutex<Server<'static, MAX_SESSIONS>>>,
    session: &mut Session,
    channel: &mut TcpChannel,
) -> Result<bool> {
    let received = channel.read(session.rx_mut()).await.map_err(|e| anyhow!("read: {e:?}"))?;
    session.set_rx_len(received.apdu_len() as usize);

    let keep = {
        let mut srv = server.lock().await;
        srv.process_request(session, received)
            .map_err(|e| anyhow!("request: {e:?}"))?
    };

    channel.write(session.tx()).await.map_err(|e| anyhow!("write: {e:?}"))?;
    session.clear_rx();
    Ok(keep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosempdu::acse::{AARQapdu, ACSEApdu, ApplicationContextName, AssociationResult};
    use cosempdu::apdu::{CosemAttributeDescriptor, GetDataResult, GetRequest, GetResponse, InvokeIdAndPriority};
    use cosempdu::apdu_sn::InitiateRequest;
    use cosempdu::buffer::ByteBuffer;

    /// Реальный AARQ WPDU от DLMS-клиента (LN без шифрования): версия 1, src=16,
    /// dst=1 (Wrapper-порт сервера), длина APDU 31. Хвост InitiateRequest
    /// `1E 5D FF FF` (vaa-name) проект игнорирует при разборе.
    const AARQ_WPDU: &[u8] = &[
        0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x1F,
        0x60, 0x1D, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
        0xBE, 0x10, 0x04, 0x0E,
        0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x62, 0x1E, 0x5D, 0xFF, 0xFF,
    ];

    /// Формирует WPDU с AARQ (клиентский запрос ассоциации).
    fn make_aarq_wpdu() -> Vec<u8> {
        let req = InitiateRequest {
            dedicated_key: None,
            response_allowed: true,
            proposed_quality_of_service: None,
            proposed_dlms_version_number: 6,
            proposed_conformance: Conformance([0x00, 0x7E, 0x1F]),
            client_max_receive_pdu_size: 1200,
        };
        let mut ui = [0u8; 64];
        let n = req.put(&mut ByteBuffer::new(&mut ui)).unwrap();

        let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        aarq.user_information = Some(&ui[..n]);
        let mut aarq_bytes = [0u8; 256];
        let m = aarq.put(&mut ByteBuffer::new(&mut aarq_bytes)).unwrap();

        // Клиент: source_port = свой (1), destination_port = сервера (1).
        let setting = Wrapper::new(1, 1);
        let mut wpdu = vec![0u8; 8 + m];
        let mut buf = ByteBuffer::new(&mut wpdu);
        setting.put(&mut buf, |b| b.write(&aarq_bytes[..m])).unwrap();
        wpdu
    }

    /// Формирует WPDU с Get-Request (чтение `value` регистра `REG_OBJ`, attr 2).
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

        // Клиент: source_port = 16, destination_port = 1 (порт сервера).
        let setting = Wrapper::new(16, 1);
        let mut wpdu = vec![0u8; 8 + n];
        let mut buf = ByteBuffer::new(&mut wpdu);
        setting.put(&mut buf, |b| b.write(&apdu[..n])).unwrap();
        wpdu
    }

    #[tokio::test]
    async fn tcp_handshake_end_to_end() {
        let mut server: Server<'static, MAX_SESSIONS> =
            Server::<'static, MAX_SESSIONS>::with_capacity(OBJECTS, SERVER_CONFORMANCE);
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
        let wpdu = make_aarq_wpdu();
        socket.write_all(&wpdu).await.unwrap();

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

    /// Полный цикл: AARQ → AARE, затем Get-Request → Get-Response.
    #[tokio::test]
    async fn tcp_get_end_to_end() {
        let mut server: Server<'static, MAX_SESSIONS> =
            Server::<'static, MAX_SESSIONS>::with_capacity(OBJECTS, SERVER_CONFORMANCE);
        server.set_wport(1);
        server
            .add_static(
                REG_OBJ.value(),
                &REG_VALUE,
                Access { read: AccessMask::PUBLIC, write: AccessMask::CONFIGURATOR },
            )
            .unwrap();
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

        // 1) Ассоциация: AARQ → AARE.
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
            GetResponse::Normal { invoke, result: GetDataResult::Data(r) } => {
                assert_eq!(invoke.invoke_id(), 1);
                // DoubleLongUnsigned(100) = [0x06, 0x00, 0x00, 0x00, 0x64].
                assert_eq!(r.as_bytes(), &[0x06, 0x00, 0x00, 0x00, 0x64]);
            }
            _ => panic!("expected GetResponse::Normal with data"),
        }
    }

    /// Клиент: подключается, шлёт AARQ и проверяет, что получил AARE (accepted).
    async fn run_client(addr: std::net::SocketAddr) {
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

    /// Два клиента одновременно ассоциируются с сервером (2 сессии из MAX_SESSIONS).
    #[tokio::test]
    async fn two_concurrent_clients() {
        let mut server: Server<'static, MAX_SESSIONS> =
            Server::<'static, MAX_SESSIONS>::with_capacity(OBJECTS, SERVER_CONFORMANCE);
        server.set_wport(1);
        let server = Arc::new(Mutex::new(server));

        let mut listener = TcpListener {
            inner: tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        };
        let addr = listener.inner.local_addr().unwrap();

        // accept-цикл на 2 соединения.
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            for _ in 0..2 {
                let channel = listener.accept().await.unwrap();
                let s = Arc::clone(&srv);
                tokio::spawn(handle_connection(s, channel));
            }
        });

        // Два клиента одновременно шлют AARQ и ждут AARE.
        tokio::join!(run_client(addr), run_client(addr));
    }
}
