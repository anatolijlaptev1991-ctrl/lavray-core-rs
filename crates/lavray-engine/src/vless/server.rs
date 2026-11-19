// SPDX-License-Identifier: GPL-3.0-only

//! Тестовый VLESS-сервер (e2e loopback): TCP (plain) или TLS (rcgen
//! self-signed), разбор запроса, ответ [0][0], relay. Только loopback-цели.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::vmess::client::uuid_bytes;

/// Запущенный тестовый сервер.
pub struct VlessTestServer {
    /// Локальный адрес.
    pub addr: std::net::SocketAddr,
    stop: tokio::sync::watch::Sender<bool>,
}

impl VlessTestServer {
    /// Остановить.
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

/// Поднять на :0 (plain TCP) для UUID.
pub async fn start(user_id: &str) -> std::io::Result<VlessTestServer> {
    start_inner(user_id, Mode::Plain).await
}

/// Поднять на :0 c TLS (self-signed localhost).
pub async fn start_tls(user_id: &str) -> std::io::Result<VlessTestServer> {
    start_inner(user_id, Mode::Tls).await
}

/// Поднять на :0 с WebSocket (Upgrade → фреймы, plain TCP).
pub async fn start_ws(user_id: &str) -> std::io::Result<VlessTestServer> {
    start_inner(user_id, Mode::Ws).await
}

/// Режим тест-сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Plain,
    Tls,
    Ws,
}

async fn start_inner(user_id: &str, mode: Mode) -> std::io::Result<VlessTestServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let uid = uuid_bytes(user_id).ok_or_else(|| std::io::Error::other("uuid"))?;

    let acceptor = tls_acceptor(mode);
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
                    let acceptor = acceptor.clone();
                    let mode = mode;
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, acceptor, &uid, mode).await {
                            eprintln!("vless-test-server: {e}");
                        }
                    });
                }
            }
        }
    });
    Ok(VlessTestServer {
        addr,
        stop: stop_tx,
    })
}

use super::relay_target::relay_target;

async fn serve(
    stream: TcpStream,
    acceptor: Option<TlsAcceptor>,
    uid: &[u8; 16],
    mode: Mode,
) -> std::io::Result<()> {
    match mode {
        Mode::Plain => relay_target(stream, uid).await,
        Mode::Tls => {
            let tls = acceptor.expect("Tls-режим").accept(stream).await?;
            relay_target(tls, uid).await
        }
        Mode::Ws => {
            let ws = crate::ws::server_stream::accept(stream).await?;
            relay_target(ws, uid).await
        }
    }
}

/// Разделить generic-поток на половины (Box-обёртки).
pub(super) fn tokio_util_split<S>(s: S) -> (crate::relay::UpRead, crate::relay::UpWrite)
where
    S: AsyncReadExt + AsyncWriteExt + Send + 'static,
{
    let (r, w) = tokio::io::split(s);
    (Box::pin(r), Box::pin(w))
}

/// rcgen-акцептор для Tls-режега (None в остальных).
fn tls_acceptor(mode: Mode) -> Option<TlsAcceptor> {
    if mode != Mode::Tls {
        return None;
    }
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
        .map_err(|e| std::io::Error::other(format!("rcgen: {e}")))
        .ok()?;
    let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
        tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
    );
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .map_err(|e| std::io::Error::other(format!("cert: {e}")))
        .ok()?;
    Some(TlsAcceptor::from(std::sync::Arc::new(cfg)))
}
