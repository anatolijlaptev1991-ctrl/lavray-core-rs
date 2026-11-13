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

pub use detail::{
    ChainDetail, CustomDetail, Detail, Hysteria2Detail, NaiveDetail, ShadowsocksDetail,
    SocksHttpDetail, TrojanVlessDetail, TuicDetail, VMessDetail,
};
pub use group::{Group, GroupKind, SubscriptionInfo};
pub use profile::{Profile, ProfileType, TestResult, TrafficCounters};
