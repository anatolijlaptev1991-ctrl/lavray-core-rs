// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-model
//!
//! Каноническая модель данных LAVRay — перепись Go `lavray/core/internal/model`
//! на Rust: bean-иерархия профилей (порт fmt/*Bean.hpp nekoray), группы,
//! канонический JSON. Имена полей — snake_case, контракт `proto/lavray.proto`.

pub mod detail;
pub mod group;
pub mod profile;
mod profile_serde;
pub mod stream;

pub use detail::{
    ChainDetail, CustomDetail, Detail, Hysteria2Detail, NaiveDetail, ShadowsocksDetail,
    SocksHttpDetail, TrojanVlessDetail, TuicDetail, VMessDetail,
};
pub use group::{Group, GroupKind, SubscriptionInfo};
pub use profile::{Profile, ProfileType, TestResult, TrafficCounters};
pub use stream::StreamSettings;

/// Профиль «свой полный конфиг» (CUSTOM_CONFIG, core internal-full): конфиг
/// ядра берётся из профиля целиком (паритет Go `model.IsInternalFull`).
#[must_use]
pub fn is_internal_full(p: &Profile) -> bool {
    p.r#type == ProfileType::CustomConfig
        && matches!(&p.detail, Some(Detail::Custom(d)) if d.core == "internal-full")
}
