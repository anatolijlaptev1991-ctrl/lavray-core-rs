// SPDX-License-Identifier: GPL-3.0-only

//! UDP tproxy-inbound (gateway, паритет sing-box `tproxy` UDP-части):
//! socket с IP_TRANSPARENT + IP_RECVORIGDSTADDR (lavray-sys); NAT-таблица
//! клиент → { UdpPipe движка (VLESS/Hy2/TUIC UDP), reply-сокет bind
//! orig_dst }, TTL-чистка. Ответы клиенту уходят С адреса реальной цели.
//! Правила nftables: `meta l4proto udp tproxy to :port mark 1` + ip rule.
#![cfg(target_os = "linux")]

use crate::addr::TargetAddr;
use crate::direct::Outbound;
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
    /// Выбранный outbound (UDP-канал движка: VLESS/Hysteria2/TUIC).
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

/// Reply-сокет: bind(orig_dst) (IP_TRANSPARENT) — ответы клиенту
/// «от цели».
fn reply_socket(orig_dst: &SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    let sock = Socket::new(
        Domain::for_address(*orig_dst),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    sock.set_ip_transparent(true)?;
    sock.bind(&(*orig_dst).into())?;
    sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(sock))
}

/// NAT-запись: UDP-канал движка + reply bind(orig_dst).
pub struct NatEntry {
    /// Сокет ответов клиенту (src = цель).
    pub reply: Arc<tokio::net::UdpSocket>,
    /// Цель пакета (= orig_dst при tproxy).
    pub target: SocketAddr,
    /// Время последнего пакета клиента.
    pub last: Instant,
    /// Данные клиента → pump-задаче (pipe внутри).
    pub to_up: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

/// NAT-таблица: клиент → запись.
pub type Nat = Arc<Mutex<HashMap<SocketAddr, NatEntry>>>;

/// Создать/обновить NAT-запись (если нет — reply bind(orig_dst) +
/// UdpPipe движка + spawn задачи pump ответов).
pub async fn nat_get_or_create(
    nat: &Nat,
    client: SocketAddr,
    orig_dst: SocketAddr,
    transparent: bool,
    outbound: &Arc<Outbound>,
) -> Result<
    (
        Arc<tokio::net::UdpSocket>,
        tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ),
    UdpTproxyError,
> {
    let _ = transparent; // сейчас NAT всегда bind(orig_dst); UDP-transparent-путь — остаток
    let mut table = nat.lock().await;
    if let Some(e) = table.get_mut(&client) {
        e.last = Instant::now();
        return Ok((Arc::clone(&e.reply), e.to_up.clone()));
    }
    let reply = Arc::new(reply_socket(&orig_dst)?);
    let target = TargetAddr::Ip(orig_dst.ip(), orig_dst.port());
    let mut pipe = crate::udp_pipe::udp_connect(outbound, &target)
        .await
        .map_err(|e| UdpTproxyError(format!("udp pipe: {e}")))?;
    // Канал клиент → pipe (pump-задача держит pipe и отправляет).
    let (to_up, mut from_run) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let reply_for_task = Arc::clone(&reply);
    tokio::spawn(async move {
        let reply = reply_for_task;
        let buf = vec![0u8; 65_535];
        loop {
            tokio::select! {
                data = from_run.recv() => {
                    match data {
                        Some(d) if !d.is_empty() => {
                            if pipe.send(&d).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                read = pipe.recv() => {
                    match read {
                        Ok(d) => {
                            if reply.send_to(&d, client).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let _ = buf;
    });
    table.insert(
        client,
        NatEntry {
            reply: Arc::clone(&reply),
            target: orig_dst,
            last: Instant::now(),
            to_up: to_up.clone(),
        },
    );
    Ok((Arc::clone(&reply), to_up))
}
