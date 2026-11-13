// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-api
//!
//! API-сервисы LAVRay (tonic) поверх store/cfgbuild/model — волна 6. Контракт
//! `lavray-proto` (lavray.v1). Реализации сервисов принимают общее хранилище
//! `Arc<Mutex<Store>>`. Начальный вертикальный срез: SettingsService.

pub mod convert;
pub mod settings;

pub use settings::SettingsServiceImpl;
