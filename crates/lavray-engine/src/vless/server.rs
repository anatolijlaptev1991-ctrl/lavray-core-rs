// SPDX-License-Identifier: GPL-3.0-only

//! Тестовый VLESS-сервер (e2e loopback): TCP (plain) или TLS (rcgen
//! self-signed), разбор запроса, ответ [0][0], relay. Только loopback-цели.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::addr::TargetAddr;
use crate::relay;
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
    start_inner(user_id, false).await
}

/// Поднять на :0 c TLS (self-signed localhost).
pub async fn start_tls(user_id: &str) -> std::io::Result<VlessTestServer> {
    start_inner(user_id, true).await
}

async fn start_inner(user_id: &str, tls: bool) -> std::io::Result<VlessTestServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let uid = uuid_bytes(user_id).ok_or_else(|| std::io::Error::other("uuid"))?;

    let acceptor = if tls {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .map_err(|e| std::io::Error::other(format!("rcgen: {e}")))?;
        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
            tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
                cert.key_pair.serialize_der(),
            ),
        );
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .map_err(|e| std::io::Error::other(format!("cert: {e}")))?;
        Some(TlsAcceptor::from(Arc::new(cfg)))
    } else {
        None
    };

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
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, acceptor, &uid).await {
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

async fn serve(
    stream: TcpStream,
    acceptor: Option<TlsAcceptor>,
    uid: &[u8; 16],
) -> std::io::Result<()> {
    match acceptor {
        None => relay_target(stream, uid).await,
        Some(a) => {
            let tls = a.accept(stream).await?;
            relay_target(tls, uid).await
        }
    }
}

async fn relay_target<S>(mut stream: S, uid: &[u8; 16]) -> std::io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    // [ver][uuid16][addons][cmd][addr]
    let mut head = [0u8; 18];
    stream.read_exact(&mut head).await?;
    if head[0] != 0 {
        return Err(std::io::Error::other("vless: версия запроса"));
    }
    if &head[1..17] != uid {
        return Err(std::io::Error::other("vless: uuid отвергнут"));
    }
    let addons = head[17] as usize;
    if addons > 0 {
        let mut skip = vec![0u8; addons];
        stream.read_exact(&mut skip).await?;
        return Err(std::io::Error::other(
            "vless-тест: addons/flow не поддерживается тест-сервером",
        ));
    }
    // Читаем cmd+порт+ATYP по мере разбора: сначала 3 байта.
    let mut pre = [0u8; 3];
    stream.read_exact(&mut pre).await?;
    if pre[0] != 1 {
        return Err(std::io::Error::other("vless: только TCP"));
    }
    let port = u16::from_be_bytes([pre[1], pre[2]]);
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    let target = match atyp[0] {
        0x01 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            TargetAddr::Ip(std::net::IpAddr::V4(b.into()), port)
        }
        0x02 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            stream.read_exact(&mut d).await?;
            let name =
                String::from_utf8(d).map_err(|_| std::io::Error::other("vless: fqdn utf8"))?;
            TargetAddr::Domain(name, port)
        }
        0x03 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            TargetAddr::Ip(std::net::IpAddr::V6(b.into()), port)
        }
        other => return Err(std::io::Error::other(format!("vless: ATYP {other:#04x}"))),
    };

    // Домен резолвится, цель обязана быть loopback.
    let (host, port) = match &target {
        TargetAddr::Ip(ip, p) => {
            if !ip.is_loopback() {
                return Err(std::io::Error::other("vless-тест: только loopback"));
            }
            (ip.to_string(), *p)
        }
        TargetAddr::Domain(d, p) => (d.clone(), *p),
    };
    let dest = TcpStream::connect((host.as_str(), port)).await?;
    let peer = dest
        .peer_addr()
        .map_err(|_| std::io::Error::other("vless-тест: только loopback"))?;
    if !peer.ip().is_loopback() {
        return Err(std::io::Error::other("vless-тест: только loopback"));
    }

    // Ответ: [0][0], затем прозрачный релей.
    stream.write_all(&[0, 0]).await?;
    let (r, w) = tokio_util_split(stream);
    let (dr, dw) = dest.into_split();
    relay::pump(dr, dw, r, w, Vec::new()).await?;
    Ok(())
}

/// Разделить generic-поток на половины (Box-обёртки).
fn tokio_util_split<S>(s: S) -> (crate::relay::UpRead, crate::relay::UpWrite)
where
    S: AsyncReadExt + AsyncWriteExt + Send + 'static,
{
    let (r, w) = tokio::io::split(s);
    (Box::pin(r), Box::pin(w))
}
