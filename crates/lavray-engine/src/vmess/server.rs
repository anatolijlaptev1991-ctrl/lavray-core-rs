// SPDX-License-Identifier: GPL-3.0-only

//! Тестовый VMess-сервер (e2e loopback): слушатель + тонкий serve;
//! разбор запроса — parse.rs, ответ-заголовок — resp.rs. Только
//! loopback-цели (домен резолвится системно).

use tokio::net::{TcpListener, TcpStream};

use crate::addr::TargetAddr;
use crate::relay;
use crate::vmess::body::BodyReader;
use crate::vmess::client::uuid_bytes;
use crate::vmess::header::Security;
use crate::vmess::kdf::{sha256_16, user_key};
use crate::vmess::parse::parse_request;
use crate::vmess::resp::send_response_header;
use crate::vmess::write::BodyWriter;

/// Запущенный тестовый сервер.
pub struct VmessTestServer {
    /// Локальный адрес.
    pub addr: std::net::SocketAddr,
    stop: tokio::sync::watch::Sender<bool>,
}

impl VmessTestServer {
    /// Остановить.
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

/// Поднять на :0 для UUID/security.
pub async fn start(user_id: &str, security: Security) -> std::io::Result<VmessTestServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let uid = uuid_bytes(user_id).ok_or_else(|| std::io::Error::other("uuid"))?;
    let mut stop_task = stop_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_task.changed() => {
                    if *stop_task.borrow_and_update() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, &uid, security).await {
                            eprintln!("vmess-test-server: {e}");
                        }
                    });
                }
            }
        }
    });
    Ok(VmessTestServer {
        addr,
        stop: stop_tx,
    })
}

async fn serve(mut stream: TcpStream, uid: &[u8; 16], security: Security) -> std::io::Result<()> {
    let key = user_key(uid);
    let (req_key, req_nonce, target) = parse_request(&mut stream, &key).await?;
    send_response_header(&mut stream, &req_key, &req_nonce).await?;

    // Тело: чтение клиента — reqKey, запись — respKey (SHA256-производные).
    let resp_key = sha256_16(&req_key);
    let resp_nonce = sha256_16(&req_nonce);

    // Домен резолвится системно (паритет), но цель обязана быть loopback —
    // тестовый сервер не является открытой прокси.
    let (host, port) = match &target {
        TargetAddr::Ip(ip, p) => {
            if !ip.is_loopback() {
                return Err(std::io::Error::other("vmess-тест: только loopback"));
            }
            (ip.to_string(), *p)
        }
        TargetAddr::Domain(d, p) => (d.clone(), *p),
    };
    let dest = TcpStream::connect((host.as_str(), port)).await?;
    let peer = dest
        .peer_addr()
        .map_err(|_| std::io::Error::other("vmess-тест: только loopback"))?;
    if !peer.ip().is_loopback() {
        return Err(std::io::Error::other("vmess-тест: только loopback"));
    }

    let (r, w) = stream.into_split();
    let rd = BodyReader::new(r, security, &req_key, &req_nonce);
    let wr = BodyWriter::new(w, security, &resp_key, &resp_nonce, None);
    let (dr, dw) = dest.into_split();
    relay::pump(dr, dw, Box::pin(rd), Box::pin(wr), Vec::new()).await?;
    Ok(())
}
