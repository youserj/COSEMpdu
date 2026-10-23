//! Desktop DLMS/COSEM сервер поверх TCP (COSEM Wrapper + ACSE + xDLMS).
//!
//! Принимает TCP-соединения (по умолчанию `127.0.0.1:4059`), конкурентно
//! обслуживает каждое через `tokio::spawn`, и выполняет ассоциацию:
//! приём `AARQ` → согласование conformance → отправка `AARE`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use cosempdu::apdu_sn::Conformance;
use cosempdu::buffer::Reader;
use cosempdu::error::Error as CosemError;
use dlms1::ic::InterfaceClass;
use server::{Channel, Listener, Media, Server, Wrapper, WrapperSetting};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Адрес/порт прослушивания (стандартный DLMS/COSEM-over-TCP порт 4059).
const BIND_ADDR: &str = "127.0.0.1:4059";

/// Число одновременных DLMS-сессий (compile-time; пулы транспорта следуют этому `N`).
const MAX_SESSIONS: usize = 3;

/// Предлагаемый сервером conformance (LN, без шифрования; базовый набор GET/SET/ACTION).
const SERVER_CONFORMANCE: Conformance = Conformance([0x00, 0x7E, 0x1F]);

/// Пустой каталог объектов: для демо хендшейка реестр атрибутов не нужен.
static OBJECTS: &[&dyn InterfaceClass] = &[];

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
    type Frame = WrapperSetting;

    async fn read(&mut self, buf: &mut [u8]) -> Result<WrapperSetting, CosemError> {
        // Wrapper-заголовок (8 байт) — сразу в buf. `read_exact` сам дозапрашивает,
        // если сегмент пришёл частями (< 8 байт).
        if buf.len() < 8 {
            return Err(CosemError::NotEnoughSpace { needed: 8 });
        }
        self.read_exact_timeout(&mut buf[..8]).await?;

        // Длина APDU из заголовка.
        let setting = WrapperSetting::get(&mut Reader::new(&buf[..8]))?;
        let total = 8 + setting.apdu_len() as usize;
        if total > buf.len() {
            return Err(CosemError::NotEnoughSpace { needed: total });
        }

        // APDU — сразу в buf[8..total].
        self.read_exact_timeout(&mut buf[8..total]).await?;
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

/// Обслуживание одного соединения: read → associate → write, до закрытия/таймаута.
async fn handle_connection(
    server: Arc<Mutex<Server<'static, MAX_SESSIONS>>>,
    mut channel: TcpChannel,
) -> Result<()> {
    let idx = server.lock().await.on_connect(Media::Tcp)?;
    let result = run_session(&server, idx, &mut channel).await;
    // Всегда освобождаем сессию (сброс в Idle): и при успехе, и при таймауте/ошибке.
    server.lock().await.on_disconnect(idx);
    result
}

/// Цикл обслуживания сессии: по кадру (read → validate → accept → write),
/// с блокировкой сервера на каждый кадр.
async fn run_session(
    server: &Arc<Mutex<Server<'static, MAX_SESSIONS>>>,
    idx: usize,
    channel: &mut TcpChannel,
) -> Result<()> {
    loop {
        let mut srv = server.lock().await;
        srv.handle_frame(idx, channel)
            .await
            .map_err(|e| anyhow!("frame: {e:?}"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosempdu::acse::{AARQapdu, ACSEApdu, ApplicationContextName};
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
        let mut setting = WrapperSetting::new(1);
        setting.set_destination_port(1);
        let mut wpdu = vec![0u8; 8 + m];
        let k = setting
            .put(&aarq_bytes[..m], &mut ByteBuffer::new(&mut wpdu))
            .unwrap();
        wpdu.truncate(k);
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
        let setting = WrapperSetting::get(&mut Reader::new(&header)).unwrap();
        let mut apdu = vec![0u8; setting.apdu_len() as usize];
        socket.read_exact(&mut apdu).await.unwrap();

        let acse = ACSEApdu::get(&mut Reader::new(&apdu)).unwrap();
        match acse {
            ACSEApdu::Aare(a) => assert_eq!(a.result, 0),
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// Клиент: подключается, шлёт AARQ и проверяет, что получил AARE (accepted).
    async fn run_client(addr: std::net::SocketAddr) {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket.write_all(AARQ_WPDU).await.unwrap();

        let mut header = [0u8; 8];
        socket.read_exact(&mut header).await.unwrap();
        let setting = WrapperSetting::get(&mut Reader::new(&header)).unwrap();
        let mut apdu = vec![0u8; setting.apdu_len() as usize];
        socket.read_exact(&mut apdu).await.unwrap();

        let acse = ACSEApdu::get(&mut Reader::new(&apdu)).unwrap();
        match acse {
            ACSEApdu::Aare(a) => assert_eq!(a.result, 0),
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
