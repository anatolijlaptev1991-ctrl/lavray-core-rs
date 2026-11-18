// SPDX-License-Identifier: GPL-3.0-only

//! Активный набор и DNS-переопределения (порт Go `api/routing_service.go`
//! activePresetID/setActivePreset + `api/dns_choice.go` dropDNSChoice).
//! F2 (аудит №7): активный пресет — в settings (единственный источник при
//! сборке конфига), не в meta.

#![allow(clippy::result_large_err)] // tonic::Status велик по природе контракта
use lavray_store::Store;
use tonic::Status;

/// Ключ settings с id активного набора (JSON-строка).
pub const SETTING_ACTIVE_PRESET: &str = "routing.active_preset";

/// Ключ meta с переопределениями карточек DNS (JSON map id → choice).
pub const META_DNS_OVERRIDE: &str = "routing.dns_override";

/// Id активного набора; пусто — «global» (как Go activePresetID).
#[must_use]
pub fn active_preset_id(st: &Store) -> String {
    let raw = st.get_setting(SETTING_ACTIVE_PRESET).ok().flatten();
    let id = raw
        .as_ref()
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str::<String>(s).ok())
        .unwrap_or_default();
    if id.is_empty() {
        "global".to_string()
    } else {
        id
    }
}

/// Записать id активного набора (JSON-строкой, как ActivatePreset).
pub fn set_active_preset(st: &Store, id: &str) -> Result<(), Status> {
    let encoded =
        serde_json::to_string(id).map_err(|e| Status::internal(format!("активный набор: {e}")))?;
    st.set_setting(SETTING_ACTIVE_PRESET, &serde_json::Value::String(encoded))
        .map_err(|e| Status::internal(format!("запись активного набора: {e}")))
}

/// Убрать DNS-переопределение удалённого набора (no-op, если его не было).
/// Повреждённая карта — DATA_LOSS (не затираем молча).
pub fn drop_dns_choice(st: &Store, preset_id: &str) -> Result<(), Status> {
    let Some(raw) = st
        .get_meta(META_DNS_OVERRIDE)
        .map_err(|e| Status::internal(format!("чтение DNS-карточек: {e}")))?
    else {
        return Ok(());
    };
    let mut all: std::collections::BTreeMap<String, serde_json::Value> = serde_json::from_str(&raw)
        .map_err(|e| {
            Status::data_loss(format!(
                "повреждена запись DNS-карточек (meta {META_DNS_OVERRIDE}): {e}"
            ))
        })?;
    if all.remove(preset_id).is_none() {
        return Ok(());
    }
    let encoded =
        serde_json::to_string(&all).map_err(|e| Status::internal(format!("DNS-карточки: {e}")))?;
    st.set_meta(META_DNS_OVERRIDE, &encoded)
        .map_err(|e| Status::internal(format!("запись DNS-карточек: {e}")))
}
