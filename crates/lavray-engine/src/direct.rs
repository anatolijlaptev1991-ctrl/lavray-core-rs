// SPDX-License-Identifier: GPL-3.0-only

//! Outbound-ы волны 7a. `Outbound` — enum (не dyn): горячий путь без
//! аллокаций на диспатч; новые протоколы (SS/trojan/…) — варианты enum-а.

use std::time::Duration;

use tokio::net::TcpStream;

use crate::addr::TargetAddr;

/// Таймаут установки исходящего соединения (паритет sing-box 5 c).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Исходящий канал.
#[derive(Debug, Clone, Default)]
pub enum Outbound {
    /// Напрямую (волна 7a; «proxy»-протоколы — 7b+).
    #[default]
    Direct,
}

impl Outbound {
    /// Установить соединение к цели.
    pub async fn connect(&self, target: &TargetAddr) -> std::io::Result<TcpStream> {
        match self {
            Self::Direct => connect_direct(target).await,
        }
    }
}

/// Прямое соединение: системный резолвер + connect с таймаутом.
pub async fn connect_direct(target: &TargetAddr) -> std::io::Result<TcpStream> {
    let host = target.host_string();
    let port = target.port();
    // tokio::net::TcpStream::connect((host, port)) не даёт контроля таймаута
    // на резолв: оборачиваем весь шаг в tokio::time::timeout.
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect {target}: таймаут {CONNECT_TIMEOUT:?}"),
            )
        })?
}
