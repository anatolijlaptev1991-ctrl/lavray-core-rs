// SPDX-License-Identifier: GPL-3.0-only

//! Trojan (волна 7c): клиент поверх rustls; `server` — тестовый партнёр
//! e2e (rcgen self-signed, loopback-only).

pub mod client;
pub mod server;

pub use client::TrojanOutbound;
