// SPDX-License-Identifier: GPL-3.0-only

//! UDP tproxy-inbound (gateway, паритет sing-box `tproxy` UDP-части):
//! socket с IP_TRANSPARENT + IP_RECVORIGDSTADDR (lavray-sys); NAT-таблица
//! клиент → entry { sock: bind(orig_dst), target }, TTL-чистка. Ответы
//! клиенту уходят С адреса реальной цели (bind orig_dst).
//! Правила nftables: `meta l4proto udp tproxy to :port mark 1` + ip rule.
#![cfg(target_os = "linux")]

use crate::tun_outbound::Outbound;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Конфиг UDP tproxy-inbound.
#[derive(Debug, Clone)]
pub struct UdpTproxyConfig {
    /// Адрес прослушивания (перехват TPROXY, обычно 0.0.0.0:7894).
    pub listen: SocketAddr,
    /// Выбранный outbound (для UDP-целей через движок).
    pub outbound: Outbound,
    /// TTL NAT-записи (дефолт 60 с).
    pub nat_ttl: Duration,
}

/// Ошибка UDP tproxy.
#[derive(Debug)]
pub struct UdpTproxyError(pub String);
impl std::fmt::Display for UdpTproxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "udp tproxy: {}", self.0)
    }
}
impl std::error::Error for UdpTproxyError {}

impl From<std::io::Error> for UdpTproxyError {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

/// Прозрачный UDP-сокет: bind + IP_TRANSPARENT + orig-dst cmsg.
pub(crate) fn transparent_udp(addr: &SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use std::os::fd::AsRawFd as _;
    let sock = Socket::new(Domain::for_address(*addr), Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_ip_transparent(true)?;
    sock.bind(&(*addr).into())?;
    lavray_sys::enable_recv_orig_dst(sock.as_raw_fd())?;
    Ok(sock.into())
}

/// Upstream-сокет записи: bind на orig_dst (ответы «от цели»),
/// отправка клиентских данных в цель send_to(target).
pub fn upstream_socket(
    orig_dst: &SocketAddr,
    transparent: bool,
) -> std::io::Result<tokio::net::UdpSocket> {
    let sock = Socket::new(
        Domain::for_address(*orig_dst),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    // IP_TRANSPARENT требует CAP_NET_ADMIN — нужен на роутере (bind чужого
    // адреса); на loopback-тестах выключается.
    if transparent {
        sock.set_ip_transparent(true)?;
    }
    sock.bind(&(*orig_dst).into())
        .map_err(|e| std::io::Error::new(e.kind(), format!("bind {orig_dst}: {e}")))?;
    sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(sock))
}

/// NAT-запись: upstream bind(orig_dst), цель, время последнего пакета.
pub struct NatEntry {
    /// Сокет: ответы клиенту (src = цель) и данные в цель.
    pub sock: Arc<tokio::net::UdpSocket>,
    /// Цель пакета (= orig_dst при tproxy).
    pub target: SocketAddr,
    /// Время последнего пакета клиента.
    pub last: Instant,
}

/// NAT-таблица: клиент → запись.
pub type Nat = Arc<Mutex<HashMap<SocketAddr, NatEntry>>>;

/// Создать/обновить NAT-запись (если нет — bind(orig_dst) + spawn задачи
/// pump ответов цели → клиенту).
pub async fn nat_get_or_create(
    nat: &Nat,
    client: SocketAddr,
    orig_dst: SocketAddr,
    reply_sock: Arc<tokio::net::UdpSocket>,
    transparent: bool,
) -> Result<Arc<tokio::net::UdpSocket>, UdpTproxyError> {
    let mut table = nat.lock().await;
    if let Some(e) = table.get_mut(&client) {
        e.last = Instant::now();
        return Ok(Arc::clone(&e.sock));
    }
    let sock = Arc::new(
        upstream_socket(&orig_dst, transparent)
            .map_err(|e| UdpTproxyError(format!("upstream bind: {e}")))?,
    );
    table.insert(
        client,
        NatEntry {
            sock: Arc::clone(&sock),
            target: orig_dst,
            last: Instant::now(),
        },
    );
    drop(table);
    // Задача ответов: цель → клиент (src = цель).
    let mut buf = vec![0u8; 65_535];
    let reply_loop = Arc::clone(&sock);
    tokio::spawn(async move {
        let sock = reply_loop;
        while let Ok((n, _)) = sock.recv_from(&mut buf).await {
            if reply_sock.send_to(&buf[..n], client).await.is_err() {
                break;
            }
        }
    });
    Ok(sock)
}
