// SPDX-License-Identifier: GPL-3.0-only

//! RoutingBean NekoRay 4.x (порт Go `presets/convert.go` NekoRayRoute):
//! файлы config/routes_box/<name>; каталог routes/ старых форков тоже.

use serde::Deserialize;

/// Маршрут NekoRay (main/NekoGui_DataStore.hpp Routing).
#[derive(Debug, Default, Deserialize)]
pub struct NekoRayRoute {
    /// direct_ip списка (многострочная строка).
    #[serde(default)]
    pub direct_ip: String,
    /// direct_domain.
    #[serde(default)]
    pub direct_domain: String,
    /// proxy_ip.
    #[serde(default)]
    pub proxy_ip: String,
    /// proxy_domain.
    #[serde(default)]
    pub proxy_domain: String,
    /// block_ip.
    #[serde(default)]
    pub block_ip: String,
    /// block_domain.
    #[serde(default)]
    pub block_domain: String,
    /// def_outbound (дефолт некора — "proxy").
    #[serde(default)]
    pub def_outbound: String,
    /// custom (JSON правил sing-box).
    #[serde(default)]
    pub custom: String,

    /// remote_dns.
    #[serde(default)]
    pub remote_dns: String,
    /// remote_dns_strategy (enum v2ray).
    #[serde(default)]
    pub remote_dns_strategy: String,
    /// direct_dns.
    #[serde(default)]
    pub direct_dns: String,
    /// direct_dns_strategy — DROP (FR-UI-148).
    #[serde(default)]
    pub direct_dns_strategy: String,
    /// dns_routing.
    #[serde(default)]
    pub dns_routing: bool,
    /// use_dns_object.
    #[serde(default)]
    pub use_dns_object: bool,
    /// dns_object (строка JSON).
    #[serde(default)]
    pub dns_object: String,
    /// dns_final_out — DROP.
    #[serde(default)]
    pub dns_final_out: String,

    /// domain_strategy — DROP (мёртвое поле).
    #[serde(default)]
    pub domain_strategy: String,
    /// outbound_domain_strategy.
    #[serde(default)]
    pub outbound_domain_strategy: String,
    /// sniffing_mode (0/1/2; 2 — DROP аудита).
    #[serde(default)]
    pub sniffing_mode: u32,

    /// Core Option некора (перенос) → dns.underlying_dns.
    #[serde(default)]
    pub underlying_dns: String,
}

/// Разобрать RoutingBean из JSON (формат проверяет вызывающий).
pub fn parse(data: &str) -> Result<NekoRayRoute, String> {
    serde_json::from_str::<NekoRayRoute>(data).map_err(|e| format!("маршрут NekoRay: {e}"))
}
