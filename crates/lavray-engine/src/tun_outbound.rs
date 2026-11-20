// SPDX-License-Identifier: GPL-3.0-only

//! Универсальный исходящий туннель poll-цикла TUN (tun_proxy):
//! VLESS / Hysteria2 / TUIC за одним интерфейсом. QUIC-стримы
//! (Hy2Stream/TuicStream) — combined (AsyncRead+AsyncWrite на одном
//! объекте): их нельзя split'ить, не дропнув живые H3 uni-потоки
//! (control/QPACK держатся открытыми всё соединение).

use crate::addr::TargetAddr;
use crate::hy2::Hy2Config;
use crate::hy2_conn::connect_with_payload;
use crate::hy2_stream::Hy2Stream;
use crate::relay::{UpRead, UpWrite};
use crate::tuic::TuicConfig;
use crate::tuic_conn::{TuicStream, connect as tuic_connect};
use crate::vless::client::{VlessOutbound, connect as vless_connect};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Исходящий протокол poll-цикла.
#[derive(Debug, Clone)]
pub enum Outbound {
    /// VLESS/Trojan (TCP+TLS).
    Vless(VlessOutbound),
    /// Hysteria2 (QUIC).
    Hy2(Hy2Config),
    /// TUIC v5 (QUIC).
    Tuic(TuicConfig),
}

/// Установленный upstream: split-половины (VLESS) или combined QUIC.
pub enum Upstream {
    Split(UpRead, UpWrite),
    Hy2(Hy2Stream),
    Tuic(TuicStream),
}

impl Outbound {
    /// Подключиться к цели через выбранный протокол.
    ///
    /// # Errors
    /// I/O / TLS / QUIC / auth — текст от нижнего слоя.
    pub async fn connect(&self, target: &TargetAddr) -> std::io::Result<Upstream> {
        match self {
            Self::Vless(v) => {
                let (r, w) = vless_connect(v, target).await?;
                Ok(Upstream::Split(r, w))
            }
            Self::Hy2(cfg) => {
                let host = target.host_string();
                let stream = connect_with_payload(cfg, &host, target.port(), &[])
                    .await
                    .map_err(std::io::Error::other)?;
                Ok(Upstream::Hy2(stream))
            }
            Self::Tuic(cfg) => {
                let server = crate::hy2_conn::resolve_server(&cfg.server, cfg.server_port)
                    .await
                    .map_err(std::io::Error::other)?;
                let stream = tuic_connect(cfg, target, server)
                    .await
                    .map_err(std::io::Error::other)?;
                Ok(Upstream::Tuic(stream))
            }
        }
    }
}

impl Upstream {
    /// Читать данные из upstream.
    ///
    /// # Errors
    /// I/O.
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Split(r, _) => r.read(buf).await,
            Self::Hy2(s) => s.read(buf).await,
            Self::Tuic(s) => s.read(buf).await,
        }
    }

    /// Записать данные в upstream.
    ///
    /// # Errors
    /// I/O.
    pub async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Split(_, w) => w.write_all(buf).await,
            Self::Hy2(s) => s.write_all(buf).await,
            Self::Tuic(s) => s.write_all(buf).await,
        }
    }

    /// Сбросить буферы (для QUIC-стримов flush обязателен).
    ///
    /// # Errors
    /// I/O.
    pub async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Split(_, w) => w.flush().await,
            Self::Hy2(s) => s.flush().await,
            Self::Tuic(s) => s.flush().await,
        }
    }

    /// Разделить на owned-половины (для tokio::io::copy в двух задачах).
    #[must_use]
    pub fn into_split(self) -> (UpRead, UpWrite) {
        match self {
            Self::Split(r, w) => (r, w),
            Self::Hy2(s) => s.split(),
            Self::Tuic(s) => s.split(),
        }
    }
}

/// Порт цели TargetAddr (vless порт() уже есть; тут унификация).
#[allow(dead_code)] // используется в тестах/будущих волнах
fn _unused_target_port(target: &TargetAddr) -> u16 {
    target.port()
}

/// Резолв сервера для tuic (делегат hy2_conn::resolve_server; IP или домен).
#[allow(dead_code)] // единая точка резолва для bridge-вызовов
pub(crate) async fn resolve_server(server: &str, port: u16) -> std::io::Result<SocketAddr> {
    crate::hy2_conn::resolve_server(server, port)
        .await
        .map_err(std::io::Error::other)
}
