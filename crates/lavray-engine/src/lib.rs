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
pub mod h3_auth;
pub mod http_connect;
pub mod hy2;
pub mod hy2_config;
pub mod hy2_stream;
pub mod reality;
pub mod relay;
pub mod server;
pub mod sniff;
pub mod socks5;
pub mod ss;
pub mod tls;
pub mod trojan;
pub mod tun;
pub mod tun_device;
pub mod vless;
pub mod vmess;
pub mod ws;

pub use addr::TargetAddr;
pub use direct::{Outbound, Transport};
pub use server::{MixedConfig, MixedServer, start};
