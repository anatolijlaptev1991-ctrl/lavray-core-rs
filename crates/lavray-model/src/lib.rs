// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-model
//!
//! Каноническая модель данных LAVRay — перепись Go `lavray/core/internal/model`
//! на Rust: bean-иерархия профилей (порт fmt/*Bean.hpp nekoray), группы,
//! канонический JSON. Имена полей — snake_case, контракт `proto/lavray.proto`.

mod canon_write;
pub mod canonjson;
pub mod customhash;
pub mod dedupkey;
pub mod detail;
pub mod geo;
mod geo_aliases;
mod geo_aliases_b;
mod geo_iso;
pub mod group;
pub mod profile;
mod profile_serde;
pub mod settings;
pub mod stream;

pub use canonjson::{canonical_json, CanonError, MAX_CANON_BYTES};
pub use customhash::{
    custom_confirmed, custom_fields_hash, has_custom_content, internal_full_json,
};
pub use dedupkey::dedup_key;
pub use detail::{
    ChainDetail, CustomDetail, Detail, Hysteria2Detail, NaiveDetail, ShadowsocksDetail,
    SocksHttpDetail, TrojanVlessDetail, TuicDetail, VMessDetail,
};
pub use geo::detect_geo;
pub use group::{Group, GroupKind, SubscriptionInfo};
pub use profile::{Profile, ProfileType, TestResult, TrafficCounters};
pub use settings::readers::{setting_readers, ReaderKind, SettingReader};
pub use settings::update::{
    SETTING_UPDATE_LAST_CHECKED, SETTING_UPDATE_LAST_URL, SETTING_UPDATE_ROOT_JSON,
    SETTING_UPDATE_ROOT_VERSION, SETTING_UPDATE_SERIAL_BETA, SETTING_UPDATE_SERIAL_STABLE,
    SETTING_UPDATE_TIMESTAMP_VERSION,
};
pub use settings::{
    backup_excluded, setting_descriptors, SettingDescriptor, SettingType, SETTING_GROUPS,
    SETTING_HWID_ID,
};
pub use stream::StreamSettings;

/// Профиль «свой полный конфиг» (CUSTOM_CONFIG, core internal-full): конфиг
/// ядра берётся из профиля целиком (паритет Go `model.IsInternalFull`).
#[must_use]
pub fn is_internal_full(p: &Profile) -> bool {
    p.r#type == ProfileType::CustomConfig
        && matches!(&p.detail, Some(Detail::Custom(d)) if d.core == "internal-full")
}
