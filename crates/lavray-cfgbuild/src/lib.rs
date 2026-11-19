// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-cfgbuild
//!
//! Конфигбилдер LAVRay — перепись Go `lavray/core/internal/cfgbuild` на Rust:
//! outbounds из профилей всех типов, цепочки (proxy/g-/c-), inbounds (mixed+TUN),
//! DNS из пресета, route-правила с rule-set из поставки .srs, cache_file,
//! allowlist-мерж custom_config. Конфиг — `serde_json::Value` (BTreeMap → ключи
//! сортируются, байт-в-байт golden с Go `json.MarshalIndent`).

mod builder;
pub mod chain;
pub mod dns;
pub mod dns_server;
pub mod error;
pub mod filekeys;
pub mod hy2ports;
pub mod inbounds;
pub mod merge;
pub mod merge_custom;
pub mod outbounds;
pub mod outbounds_quic;
pub mod route;
pub mod route_rules;
pub mod settings;
pub mod stream;
pub mod util;
pub mod validate;

pub use builder::neutral_preset;
pub use error::{Code, Error, Result};
pub use merge_custom::merge_custom_config;
pub use settings::{
    BuildSettings, InboundSettings, MuxSettings, TProxySettings, TunSettings, default_settings,
};
pub use util::Obj;

use lavray_model::{Group, Profile, is_internal_full};
use lavray_presets::Preset;
use serde_json::Value;

/// Вход сборки конфига (порт Go BuildRequest).
pub struct BuildRequest<'a> {
    /// Целевой профиль (в т.ч. chain / custom).
    pub profile: &'a Profile,
    /// Группа профиля (front_proxy_id), может быть None.
    pub group: Option<&'a Group>,
    /// None → DefaultSettings.
    pub settings: Option<&'a BuildSettings>,
    /// Обязательна для chain/front proxy.
    pub lookup: Option<&'a dyn Fn(i64) -> Result<Profile>>,
    /// Активный маршрутный пресет; None → нейтральный.
    pub preset: Option<&'a Preset>,
    /// Режим теста (пустые inbounds, без user-правил).
    pub for_test: bool,
    /// Экспорт (без auto_detect_interface).
    pub for_export: bool,
}

/// Результат сборки (порт Go BuildResult).
#[derive(Debug, Clone, Default)]
pub struct BuildResult {
    /// Итоговый конфиг sing-box.
    pub config: Obj,
    /// Тег «последней мили» цепочки, всегда "proxy".
    pub outbound_tag: String,
    /// Теги outbound'ов профиля (для allowlist-мержа custom_config).
    pub outbound_tags: Vec<String>,
    /// Теги промежуточных outbound'ов (index != 0).
    pub ignore_conn_tags: Vec<String>,
    /// Домены серверов цепочки («full:<домен>») для dns-direct.
    pub server_domains: Vec<String>,
    /// Замечания сборки, не мешающие запуску.
    pub warnings: Vec<String>,
}

/// Собрать конфиг sing-box для профиля (порт Go Build).
#[allow(clippy::needless_pass_by_value)] // BuildRequest — вход API, паритет Go
pub fn build(req: BuildRequest<'_>) -> Result<BuildResult> {
    let defaults;
    let st = if let Some(s) = req.settings {
        s
    } else {
        defaults = default_settings();
        &defaults
    };
    let mut res = BuildResult::default();

    let mut cfg = if is_internal_full(req.profile) {
        if !req.profile.custom_fields_confirmed {
            return Err(Error::invalid(
                "custom.bean.core",
                "internal-full конфиг не подтверждён: откройте diff и подтвердите (PreviewCustomFields → ConfirmCustomFields)",
            ));
        }
        builder::internal_full_config(req.profile)?
    } else {
        builder::build_sing_box_config(&req, st, &mut res)?
    };

    if !req.profile.custom_config_json.is_empty() && req.profile.custom_fields_confirmed {
        merge_custom_config(
            &mut cfg,
            &req.profile.custom_config_json,
            &res.outbound_tags,
        )?;
    }
    res.config = cfg;
    Ok(res)
}

/// Детерминированный JSON конфига (2 пробела, ключи сортированы) — паритет
/// Go `MarshalIndent`. Канонизация — ЯВНАЯ рекурсивная сортировка ключей:
/// фича preserve_order у соседних крейтов (feature-union по графу) меняет
/// serde_json::Map на IndexMap, и сортировка «сама собой» исчезла бы.
pub fn marshal_indent(cfg: &Obj) -> Result<String> {
    let sorted = canonical_sorted(&Value::Object(cfg.clone()));
    serde_json::to_string_pretty(&sorted)
        .map_err(|e| Error::invalid("config", format!("marshal config: {e}")))
}

/// Рекурсивно: объекты → BTreeMap-порядок (сортировка ключей).
fn canonical_sorted(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<&String, &Value> = map.iter().collect();
            let out: serde_json::Map<String, Value> = sorted
                .into_iter()
                .map(|(k, val)| (k.clone(), canonical_sorted(val)))
                .collect();
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonical_sorted).collect()),
        other => other.clone(),
    }
}
