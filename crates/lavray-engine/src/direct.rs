// SPDX-License-Identifier: GPL-3.0-only

//! Outbound-ы волны 7a. `Outbound` — enum (не dyn): горячий путь без
//! аллокаций на диспатч; новые протоколы (SS/trojan/…) — варианты enum-а.

use std::time::Duration;

use tokio::net::TcpStream;

use crate::addr::TargetAddr;
use crate::relay::{UpRead, UpWrite};
use crate::ss::client::{self, SsOutbound};
use crate::trojan::{self, TrojanOutbound};
use crate::vmess::{self, VmessOutbound};

/// Таймаут установки исходящего соединения (паритет sing-box 5 c).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Исходящий канал.
#[derive(Debug, Clone, Default)]
pub enum Outbound {
    /// Напрямую (волна 7a).
    #[default]
    Direct,
    /// Shadowsocks AEAD/2022 (волна 7b).
    Shadowsocks(Box<SsOutbound>),
    /// Trojan поверх TLS (волна 7c).
    Trojan(Box<TrojanOutbound>),
    /// VMess AEAD (волна 7c).
    Vmess(Box<VmessOutbound>),
}

impl Outbound {
    /// Установить туннель к цели: половины (read, write).
    pub async fn connect(&self, target: &TargetAddr) -> std::io::Result<(UpRead, UpWrite)> {
        match self {
            Self::Direct => {
                let s = connect_direct(target).await?;
                let (r, w) = s.into_split();
                Ok((Box::pin(r), Box::pin(w)))
            }
            Self::Shadowsocks(o) => {
                let (r, w) = client::connect(o, target).await?;
                Ok((Box::pin(r), Box::pin(w)))
            }
            Self::Trojan(o) => trojan::client::connect(o, target).await,
            Self::Vmess(o) => vmess::client::connect(o, target).await,
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
