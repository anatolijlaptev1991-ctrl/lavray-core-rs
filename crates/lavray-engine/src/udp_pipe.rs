// SPDX-License-Identifier: GPL-3.0-only

//! UDP-каналы outbound'ов движка (волна QUIC-UDP): VLESS (stream с
//! len16-пакетами, cmd=2 — udp_pipe_vless), hysteria2 (QUIC datagrams —
//! udp_pipe_hy2), tuic v5 (QUIC datagrams — udp_pipe_tuic).
//! Единый интерфейс UdpPipe::send/recv — цель канала фиксирована
//! (full-cone NAT udp_tproxy создаёт канал per-цель).

use crate::addr::TargetAddr;
use crate::direct::Outbound;
use crate::relay::UpRead;
use crate::udp_pipe_hy2::Hy2Udp;
use crate::udp_pipe_tuic::TuicUdp;
use crate::udp_pipe_vless::UpWriteVless;
use std::io;
use std::sync::Arc;

/// Установленный UDP-канал к цели.
pub enum UdpPipe {
    /// Прямой UDP (без прокси) — connect к цели.
    Direct(Arc<tokio::net::UdpSocket>),
    /// VLESS: TCP+TLS stream, пакеты [len16 BE][data].
    Vless(UpRead, Arc<UpWriteVless>, TargetAddr),
    /// Hysteria2: QUIC datagrams.
    Hy2(Hy2Udp, TargetAddr),
    /// TUIC v5: QUIC datagrams CommandPacket.
    Tuic(TuicUdp, TargetAddr),
}

impl UdpPipe {
    /// Отправить пакет в цель канала.
    ///
    /// # Errors
    /// I/O / QUIC.
    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Direct(sock) => sock.send(data).await.map(|_| ()),
            Self::Vless(_, w, _) => w.send(data).await,
            Self::Hy2(h, t) => h.send(data, t).await,
            Self::Tuic(tu, t) => tu.send(data, t).await,
        }
    }

    /// Принять пакет от цели (возвращает данные; адрес = цель канала).
    ///
    /// # Errors
    /// I/O / QUIC.
    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        match self {
            Self::Direct(sock) => {
                let mut buf = vec![0u8; 65_535];
                let (n, _) = sock.recv_from(&mut buf).await?;
                Ok(buf[..n].to_vec())
            }
            Self::Vless(r, _, _) => crate::udp_pipe_vless::vless_recv(r).await,
            Self::Hy2(h, _) => h.recv().await,
            Self::Tuic(t, _) => t.recv().await,
        }
    }
}

/// UDP-канал движка по протоколу outbound'а.
///
/// # Errors
/// QUIC/TLS/I/O.
pub async fn udp_connect(outbound: &Arc<Outbound>, target: &TargetAddr) -> io::Result<UdpPipe> {
    match outbound.as_ref() {
        Outbound::Direct => {
            let (host, port) = (target.host_string(), target.port());
            let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            sock.connect((host.as_str(), port)).await?;
            Ok(UdpPipe::Direct(Arc::new(sock)))
        }
        Outbound::Shadowsocks(_) | Outbound::Trojan(_) | Outbound::Vmess(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "udp: протокол без UDP-канала",
        )),
        Outbound::Vless(v) => crate::udp_pipe_vless::vless_connect(v, target).await,
        Outbound::Hy2(cfg) => crate::udp_pipe_hy2::hy2_connect(cfg, target).await,
        Outbound::Tuic(cfg) => crate::udp_pipe_tuic::tuic_connect(cfg, target).await,
    }
}
