// SPDX-License-Identifier: GPL-3.0-only

//! Карточки DNS (T-31): переопределение поверх активного пресета —
//! meta routing.dns_override, карта preset_id → выбор (вынесено из
//! dns.rs трещоткой размеров).

use lavray_store::Store;
use tonic::Status;

use crate::preset_active::{META_DNS_OVERRIDE, active_preset_id};
use crate::preset_repo;

/// Карточка DNS активного пресета (T-31).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct DnsChoice {
    pub(super) choice: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) remote_dns: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) remote_query_strategy: String,
}

/// DNS активного пресета (global-фолбонт при отсутствии).
pub(super) fn active_dns(st: &Store) -> lavray_presets::DnsBlock {
    let active = active_preset_id(st);
    if let Ok(custom) = preset_repo::read(st)
        && let Some(p) = custom.iter().find(|p| p.id == active)
    {
        return p.dns.clone();
    }
    if let Ok(builtin) = lavray_presets::builtin_presets()
        && let Some(p) = builtin.iter().find(|p| p.id == active)
    {
        return p.dns.clone();
    }
    lavray_presets::DnsBlock {
        mode: "simple".into(),
        remote_dns: "https://dns.google/dns-query".into(),
        direct_dns: "local".into(),
        ..Default::default()
    }
}

/// Выбранная карточка активного пресета (None — «Авто»).
pub(super) fn active_choice(st: &Store) -> Option<String> {
    let raw = st.get_meta(META_DNS_OVERRIDE).ok().flatten()?;
    let all: std::collections::BTreeMap<String, DnsChoice> = serde_json::from_str(&raw).ok()?;
    all.get(&active_preset_id(st)).map(|c| c.choice.clone())
}

/// Сохранить карточку активного пресета в meta-карту.
#[allow(clippy::result_large_err)] // tonic::Status велик по природе контракта
pub(super) fn save_choice(st: &Store, preset_id: &str, choice: &DnsChoice) -> Result<(), Status> {
    let raw = st
        .get_meta(META_DNS_OVERRIDE)
        .ok()
        .flatten()
        .unwrap_or_default();
    let mut all: std::collections::BTreeMap<String, DnsChoice> = if raw.trim().is_empty() {
        std::collections::BTreeMap::default()
    } else {
        serde_json::from_str(&raw)
            .map_err(|e| Status::data_loss(format!("DNS-карточки повреждены: {e}")))?
    };
    all.insert(preset_id.to_string(), choice.clone());
    let encoded =
        serde_json::to_string(&all).map_err(|e| Status::internal(format!("DNS-карточки: {e}")))?;
    st.set_meta(META_DNS_OVERRIDE, &encoded)
        .map_err(|e| Status::internal(format!("запись DNS-карточек: {e}")))
}
