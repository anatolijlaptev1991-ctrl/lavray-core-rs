// SPDX-License-Identifier: GPL-3.0-only

//! WebSocket-транспорт (волна 7e): клиент RFC 6455 — Upgrade поверх
//! TCP/TLS + бинарные фреймы; транспорт vmess/vless/trojan (network="ws").

pub mod frame;
pub mod handshake;
pub mod write;

pub use handshake::{WsDial, handshake};
