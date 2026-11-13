// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-api
//!
//! API-сервисы LAVRay (tonic) поверх store/cfgbuild/model — волна 6. Контракт
//! `lavray-proto` (lavray.v1). Реализации сервисов принимают общее хранилище
//! `Arc<Mutex<Store>>`.

pub mod convert;
pub mod group_convert;
mod groups_rpc;
pub mod profile_convert;
mod profile_detail;
mod profile_detail_quic;
mod profile_stream;
pub mod profiles;
mod profiles_core;
mod profiles_io;
pub mod settings;

pub use profiles::ProfileServiceImpl;
pub use settings::SettingsServiceImpl;
