// SPDX-License-Identifier: GPL-3.0-only

//! VLESS (волна 7d, v0 без flow): клиент поверх TLS/plain; `server` —
//! тестовый партнёр e2e (loopback-only). REALITY/vision — отдельная
//! подволна (мимикрия ClientHello), статус в ROADMAP.

pub mod client;
pub mod server;

pub use client::VlessOutbound;
