// SPDX-License-Identifier: GPL-3.0-only

//! Типы пресета `preset.schema.v1` — паритет с Go `presets.Preset/Routing/
//! ProcessRule/DNSBlock`. Поля `omitempty` в Go → `skip_serializing_if` здесь.

use crate::localized::Localized;
use serde::{Deserialize, Serialize};

/// Поддерживаемая версия схемы (минорные назад — SCHEMA §1).
pub const SCHEMA_VERSION: u32 = 1;

/// Пресет маршрутизации.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preset {
    /// Маркер схемы (`preset.schema.v1.json`).
    #[serde(rename = "$schema", default)]
    pub schema: String,
    /// Версия схемы.
    #[serde(default)]
    pub version: u32,
    /// Ревизия набора.
    #[serde(default)]
    pub revision: u32,
    /// Идентификатор набора.
    #[serde(default)]
    pub id: String,
    /// Встроенный ли набор.
    #[serde(default)]
    pub builtin: bool,
    /// Локализованное имя.
    #[serde(default)]
    pub name: Localized,
    /// Локализованное описание.
    #[serde(default)]
    pub description: Localized,
    /// Заметки мейнтейнера.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub maintainer_notes: String,
    /// Блок маршрутизации.
    #[serde(default)]
    pub routing: Routing,
    /// Блок DNS.
    #[serde(default)]
    pub dns: DnsBlock,
    /// Встроенный набор-источник копии (T-80).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    /// Ревизия набора-источника.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_revision: u32,
}

/// Блок routing (SCHEMA §2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Routing {
    /// Исходящий по умолчанию: proxy/direct/block.
    #[serde(default)]
    pub def_outbound: String,
    /// Стратегия домена исходящего.
    #[serde(default)]
    pub outbound_domain_strategy: String,
    /// Режим сниффинга (0/1; 2 — DROP аудита).
    #[serde(default)]
    pub sniffing_mode: u32,
    /// Домены через прокси.
    #[serde(default)]
    pub proxy_domain: Vec<String>,
    /// Домены напрямую.
    #[serde(default)]
    pub direct_domain: Vec<String>,
    /// Домены в блок.
    #[serde(default)]
    pub block_domain: Vec<String>,
    /// IP через прокси.
    #[serde(default)]
    pub proxy_ip: Vec<String>,
    /// IP напрямую.
    #[serde(default)]
    pub direct_ip: Vec<String>,
    /// IP в блок.
    #[serde(default)]
    pub block_ip: Vec<String>,
    /// Процессные правила (platform-scoped).
    #[serde(default)]
    pub process_rules: Vec<ProcessRule>,
    /// Пользовательские правила sing-box (JSON).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub custom_rules: String,
}

/// Процессное правило (SCHEMA §2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRule {
    /// Платформы (windows/linux/macos/openwrt); пусто — все.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<String>,
    /// Исходящий: proxy/direct/block.
    #[serde(default)]
    pub outbound: String,
    /// Имена процессов (без путей — анти-инъекция §4.3).
    #[serde(default)]
    pub process_names: Vec<String>,
}

/// Блок DNS (SCHEMA §3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsBlock {
    /// Режим: simple | advanced.
    #[serde(default)]
    pub mode: String,
    /// Удалённый DNS (DoH).
    #[serde(default)]
    pub remote_dns: String,
    /// Стратегия удалённого запроса.
    #[serde(default)]
    pub remote_query_strategy: String,
    /// Прямой DNS (провайдер).
    #[serde(default)]
    pub direct_dns: String,
    /// Маршрутизация DNS включена.
    #[serde(default)]
    pub routing_enabled: bool,
    /// Underlying DNS.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub underlying_dns: String,
    /// JSON объекта dns при mode=advanced (FR-UI-149).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub advanced_json: String,
}

/// serde-хелпер: пропуск нулевых чисел (аналог Go `omitempty` для int).
/// Сигнатура `&u32` обязательна для `skip_serializing_if`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(v: &u32) -> bool {
    *v == 0
}
