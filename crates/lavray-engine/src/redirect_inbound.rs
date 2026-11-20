// SPDX-License-Identifier: GPL-3.0-only

//! Redirect-inbound (gateway, паритет sing-box `redirect`): TCP-listener
//! с IP_TRANSPARENT, цель берётся из SO_ORIGINAL_DST (iptables/nftables
//! REDIRECT/TPROXY на роутере) → Outbound-мост (VLESS/Hy2/Tuic) →
//! bidirectional relay. Роутерная часть — `nftables.rs`.

use crate::addr::TargetAddr;
use crate::tun_outbound::Outbound;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Конфиг redirect-inbound.
#[derive(Debug, Clone)]
pub struct RedirectConfig {
    /// Адрес прослушивания (обычно 0.0.0.0:7893).
    pub listen: SocketAddr,
    /// Выбранный outbound (VLESS / Hysteria2 / TUIC).
    pub outbound: Outbound,
}

/// Ошибка gateway-цикла.
#[derive(Debug)]
pub struct GatewayError(pub String);
impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gateway: {}", self.0)
    }
}
impl std::error::Error for GatewayError {}

/// Открыть listener с SO_REUSEADDR + IP_TRANSPARENT (safe через socket2).
fn transparent_listener(addr: &SocketAddr) -> std::io::Result<TcpListener> {
    let sock = Socket::new(
        Domain::for_address(*addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    sock.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    sock.set_ip_transparent(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&(*addr).into())?;
    sock.listen(1024)?;
    let std_listener: std::net::TcpListener = sock.into();
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener).map_err(std::io::Error::other)
}

/// Цель из SO_ORIGINAL_DST (REDIRECT сохраняет исходный адрес назначения;
/// IPv4 — SO_ORIGINAL_DST, IPv6 — IP6T_SO_ORIGINAL_DST).
fn original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    let sock = socket2::SockRef::from(stream);
    if stream.local_addr()?.is_ipv4() {
        sock.original_dst()
    } else {
        sock.original_dst_ipv6()
    }?
    .as_socket()
    .ok_or_else(|| std::io::Error::other("original dst: не адрес"))
}

/// Запустить gateway-цикл: accept → original dst → outbound relay.
/// Возвращает управление после shutdown-сигнала.
///
/// # Errors
/// Listener I/O.
pub async fn run(
    cfg: RedirectConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), GatewayError> {
    let listener = transparent_listener(&cfg.listen)
        .map_err(|e| GatewayError(format!("listen {}: {e}", cfg.listen)))?;
    let outbound = Arc::new(cfg.outbound);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.map_err(|e| GatewayError(format!("accept: {e}")))?;
                let target = match original_dst(&stream) {
                    Ok(a) => TargetAddr::Ip(a.ip(), a.port()),
                    Err(e) => {
                        // нет SO_ORIGINAL_DST (сокет без REDIRECT) — разрыв
                        let _ = stream.shutdown().await;
                        eprintln!("gateway: original dst: {e}");
                        continue;
                    }
                };
                let outbound = Arc::clone(&outbound);
                tokio::spawn(async move {
                    if let Err(e) = relay(stream, target, outbound).await {
                        eprintln!("gateway relay: {e}");
                    }
                });
            }
        }
    }
}

/// Сквозная перекачка: клиент ↔ outbound (owned-половины + две задачи).
async fn relay(
    stream: TcpStream,
    target: TargetAddr,
    outbound: Arc<Outbound>,
) -> std::io::Result<()> {
    let upstream = outbound.connect(&target).await?;
    let (mut up_r, mut up_w) = upstream.into_split();
    let (mut cl_r, mut cl_w) = tokio::io::split(stream);

    let c2u = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match cl_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if up_w.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = up_w.shutdown().await;
    });
    let u2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match up_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if cl_w.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = cl_w.shutdown().await;
    });
    let _ = c2u.await;
    let _ = u2c.await;
    Ok(())
}
