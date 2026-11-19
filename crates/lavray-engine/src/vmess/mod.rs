// SPDX-License-Identifier: GPL-3.0-only

//! VMess (волна 7c, AEAD/alterId=0): KDF, заголовок, AEAD-блоки тела,
//! клиент; `server` — тестовый партнёр e2e (loopback-only). Порт
//! sing-vmess v0.2.8.

pub mod body;
pub mod client;
pub mod header;
pub mod kdf;
mod parse;
mod resp;
pub mod server;
pub mod target;
pub mod write;

pub use client::VmessOutbound;
pub use header::Security;
