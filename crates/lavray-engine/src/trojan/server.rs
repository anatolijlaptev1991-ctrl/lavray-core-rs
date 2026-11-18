// SPDX-License-Identifier: GPL-3.0-only

//! Тестовый trojan-сервер (e2e loopback): rcgen-сертификат, rustls accept,
//! проверка hex(SHA224(password)), адрес, relay к цели. Только loopback.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::addr::TargetAddr;
use crate::relay;
use crate::ss::target::parse_target;
use crate::trojan::client::password_hex;

/// Запущенный тестовый trojan-сервер.
pub struct TrojanTestServer {
    /// Локальный адрес.
    pub addr: std::net::SocketAddr,
    stop: tokio::sync::watch::Sender<bool>,
}

impl TrojanTestServer {
    /// Остановить.
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

/// Поднять trojan-сервер на :0 (ephemeral) для пароля.
pub async fn start(password: &str) -> std::io::Result<TrojanTestServer> {
    let ln = TcpListener::bind("127.0.0.1:0").await?;
    let addr = ln.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    // Самоподписанный сертификат CN=localhost (только тесты).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
        .map_err(|e| std::io::Error::other(format!("rcgen: {e}")))?;
    let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
        tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
    );
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .map_err(|e| std::io::Error::other(format!("cert: {e}")))?;
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let want = password_hex(password);
    let mut stop_task = stop_rx.clone();
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
                    let acceptor = acceptor.clone();
                    let want = want.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, acceptor, &want).await {
                            eprintln!("trojan-test-server: {e}");
                        }
                    });
                }
            }
        }
    });
    Ok(TrojanTestServer {
        addr,
        stop: stop_tx,
    })
}

async fn serve(stream: TcpStream, acceptor: TlsAcceptor, want_hex: &str) -> std::io::Result<()> {
    let mut tls = acceptor.accept(stream).await?;

    // hex-хэш CRLF.
    let mut head = vec![0u8; 56 + 2 + 1 + 255 + 2 + 2];
    let mut filled = 0usize;
    // Читаем до второго CRLF (после адреса), не дальше — чтобы не съесть
    // начало данных: адрес парсится по префиксу, остаток — relay-префикс.
    let mut got = Vec::with_capacity(128);
    loop {
        let n = tls.read(&mut head).await?;
        if n == 0 {
            return Err(std::io::Error::other("trojan: обрыв до адреса"));
        }
        got.extend_from_slice(&head[..n]);
        if got.len() > 512 {
            return Err(std::io::Error::other("trojan: голова >512"));
        }
        // Достаточно ли для адреса: ищем CRLF после 58 байт.
        if got.len() >= 58
            && let Some((target, used)) = parse_target(&got[58..])
            && got.len() >= 58 + used + 2
        {
            if &got[56..58] != b"\r\n" {
                return Err(std::io::Error::other("trojan: нет CRLF после хэша"));
            }
            if !got[..56].eq_ignore_ascii_case(want_hex.as_bytes()) {
                return Err(std::io::Error::other("trojan: пароль отвергнут"));
            }
            if &got[58 + used..58 + used + 2] != b"\r\n" {
                return Err(std::io::Error::other("trojan: нет CRLF после адреса"));
            }
            let prefix = got[58 + used + 2..].to_vec();
            return relay_to(tls, target, prefix).await;
        }
        filled += n;
        let _ = filled;
    }
}

async fn relay_to(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    target: TargetAddr,
    prefix: Vec<u8>,
) -> std::io::Result<()> {
    // Только loopback (тестовый сервер — не открытая прокси).
    let TargetAddr::Ip(ip, port) = &target else {
        return Err(std::io::Error::other("trojan-тест: только IP-цели"));
    };
    if !ip.is_loopback() {
        return Err(std::io::Error::other("trojan-тест: только loopback"));
    }
    let mut dest = TcpStream::connect((ip.to_string().as_str(), *port)).await?;
    if !prefix.is_empty() {
        dest.write_all(&prefix).await?;
    }
    let (r, w) = tokio::io::split(tls);
    let (dr, dw) = dest.into_split();
    relay::pump(dr, dw, Box::pin(r), Box::pin(w), Vec::new()).await?;
    Ok(())
}
