// SPDX-License-Identifier: GPL-3.0-only

//! Shadowsocks AEAD/2022 (волна 7b): ключи, фрейм, потоковые половины,
//! клиент; `server` — тестовый партнёр для e2e (серверной части у клиента
//! LAVRay нет, но протокол проверяется с обеих сторон).

pub mod aead;
pub mod client;
pub mod frame;
pub mod key;
pub mod server;
pub mod stream;
pub mod target;
pub mod write;

pub use client::SsOutbound;
