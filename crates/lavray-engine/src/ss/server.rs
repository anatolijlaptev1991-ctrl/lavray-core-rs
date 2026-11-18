// SPDX-License-Identifier: GPL-3.0-only

//! Тестовый SS-сервер (e2e loopback): принимает туннель, читает соль и
//! адрес из первого чанка, подключается к цели и ретранслирует. Это СЕРВЕР
//! только для тестов движка; серверной части у клиента LAVRay нет — но
//! полный паритет протокола требует обе стороны (проверка roundtrip).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::addr::TargetAddr;
use crate::relay;
use crate::ss::aead::Method;
use crate::ss::key::{identity_key, session_key};
use crate::ss::stream::SsReadHalf;
use crate::ss::target::parse_target;
use crate::ss::write::SsWriteHalf;

/// Запущенный тестовый сервер.
pub struct SsTestServer {
    /// Локальный адрес SS-сервера.
    pub addr: std::net::SocketAddr,
    stop: tokio::sync::watch::Sender<bool>,
}

impl SsTestServer {
    /// Остановить.
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

/// Поднять SS-сервер на :0 (ephemeral) для метода/пароля.
pub async fn start(method: Method, password: &str) -> std::io::Result<SsTestServer> {
    let ln = TcpListener::bind("127.0.0.1:0").await?;
    let addr = ln.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut stop_task = stop_rx.clone();
    let identity = identity_key(method, password);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_task.changed() => {
                    if *stop_task.borrow_and_update() {
                        break;
                    }
                }
                accepted = ln.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let id = identity.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, method, &id).await {
                            eprintln!("ss-test-server: {e}");
                        }
                    });
                }
            }
        }
    });
    Ok(SsTestServer {
        addr,
        stop: stop_tx,
    })
}

async fn serve(stream: TcpStream, method: Method, identity: &[u8]) -> std::io::Result<()> {
    // Соль → сессионный ключ. Split СРАЗУ: соль читаем через половину
    // (эксперимент: чтение целого stream до into_split даёт фантомный EOF
    // на следующем poll половины — Windows/mio).
    let (mut sr, w) = stream.into_split();
    let mut salt = vec![0u8; method.salt_len()];
    sr.read_exact(&mut salt).await?;
    let r = sr;
    let session = session_key(method, identity, &salt);
    let mut rd = SsReadHalf::new(r, method, &session);
    let wr = SsWriteHalf::new(w, method, &session, None);

    // Первый чанк: адрес цели (+ возможно начало данных).
    let mut head = vec![0u8; 0x4000];
    let n = rd.read(&mut head).await?;
    if n == 0 {
        return Err(std::io::Error::other("SS: пустой первый чанк"));
    }
    let Some((target, used)) = parse_target(&head[..n]) else {
        return Err(std::io::Error::other("SS: адрес цели не разобран"));
    };
    let rest = head[used..n].to_vec();

    // Цель: только loopback (тестовый сервер — не открытая прокси).
    let TargetAddr::Ip(ip, port) = &target else {
        return Err(std::io::Error::other("SS-тест: только IP-цели"));
    };
    if !ip.is_loopback() {
        return Err(std::io::Error::other("SS-тест: только loopback"));
    }
    let mut dest = TcpStream::connect((ip.to_string().as_str(), *port)).await?;
    if !rest.is_empty() {
        dest.write_all(&rest).await?;
    }
    let (dr, dw) = dest.into_split();
    let total = relay::pump(dr, dw, Box::pin(rd), Box::pin(wr), Vec::new()).await?;
    let _ = total; // статистика — в следующих волнах
    Ok(())
}
