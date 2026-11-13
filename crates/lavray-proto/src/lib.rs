// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-proto
//!
//! API-контракт LAVRay — prost/tonic типы и сервисы, сгенерированные из
//! `proto/lavray.proto` (волна 6). Контракт UI ↔ ядро (ConnectRPC/gRPC):
//! 15 сервисов, ~97 RPC. Сгенерированный код исключён из линтов/трещотки.

/// Сгенерированные типы и сервисы `lavray.v1`.
#[allow(clippy::all, clippy::pedantic, clippy::nursery)]
pub mod lavray {
    /// Пакет `lavray.v1`.
    #[allow(clippy::all, clippy::pedantic, clippy::nursery)]
    pub mod v1 {
        tonic::include_proto!("lavray.v1");
    }
}

pub use lavray::v1;
