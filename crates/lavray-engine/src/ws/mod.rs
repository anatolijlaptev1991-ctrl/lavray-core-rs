// SPDX-License-Identifier: GPL-3.0-only

//! WebSocket-транспорт (волна 7e): клиент RFC 6455 — Upgrade поверх
//! TCP/TLS + бинарные фреймы; транспорт vmess/vless/trojan (network="ws").

pub mod frame;
pub mod handshake;
mod server_read;
pub mod server_stream;
mod server_write;
pub mod write;

pub use handshake::{WsDial, handshake};
