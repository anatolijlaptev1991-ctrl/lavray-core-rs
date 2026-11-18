// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-engine
//!
//! Прокси-движок LAVRay на Rust (волна 7; решение владельца 18.11 — полный
//! Rust, без Go sing-box). Волна 7a: mixed-инбаунд (SOCKS5 + HTTP CONNECT,
//! свой парсер без зависимостей) и outbound direct — первый сквозной
//! прокси-трафик. Следующие волны добавляют протоколы в `Outbound`:
//! shadowsocks (7b), trojan/vmess (7c), vless+REALITY (7d), QUIC (7e).

pub mod addr;
pub mod direct;
pub mod http_connect;
pub mod relay;
pub mod server;
pub mod sniff;
pub mod socks5;
pub mod ss;
pub mod trojan;

pub use addr::TargetAddr;
pub use direct::Outbound;
pub use server::{MixedConfig, MixedServer, start};
