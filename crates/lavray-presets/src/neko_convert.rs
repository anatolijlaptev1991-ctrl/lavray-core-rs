// SPDX-License-Identifier: GPL-3.0-only

//! Конвертация маршрута NekoRay 4.x → пресет LAVRay (порт Go
//! `presets/convert.go`; SCHEMA §6, эталон — lav-ru golden G28).
//! DROP-поля некора — warning; *.exe → windows-only (§2.1).

use crate::neko_custom::extract_custom_rules;
use crate::neko_route::NekoRayRoute;
use crate::types::{Preset, SCHEMA_VERSION};
use crate::validate::ValidationError;
use crate::{Localized, SCHEMA_REF};

/// Метаданные пресета-приёмника (не выводятся из RoutingBean).
#[derive(Debug, Clone)]
pub struct ConvertMeta {
    /// id (обычно custom:<slug>).
    pub id: String,
    /// Имя (en).
    pub name: String,
}

/// Конвертировать RoutingBean → пресет; возвращает (пресет, warnings).
pub fn convert_neko_route(
    src: &NekoRayRoute,
    meta: &ConvertMeta,
) -> Result<(Preset, Vec<String>), ValidationError> {
    let mut warnings = Vec::new();
    let mut out = Preset {
        schema: SCHEMA_REF.into(),
        version: SCHEMA_VERSION,
        revision: 1,
        id: meta.id.clone(),
        builtin: false,
        name: {
            let mut n = Localized::new();
            n.insert("en", meta.name.clone());
            n
        },
        ..Default::default()
    };
    let r = &mut out.routing;

    // def_outbound (дефолт некора — proxy).
    r.def_outbound = if src.def_outbound.is_empty() {
        "proxy".into()
    } else {
        src.def_outbound.clone()
    };
    if !matches!(r.def_outbound.as_str(), "proxy" | "direct" | "block") {
        return Err(ValidationError(format!(
            "def_outbound: {:?} (допустимо proxy/direct/block)",
            r.def_outbound
        )));
    }

    // Стратегии: enum v2ray → LAVRay; AsIs/"" → "".
    r.outbound_domain_strategy = map_strategy(
        &src.outbound_domain_strategy,
        &mut warnings,
        "outbound_domain_strategy",
    );
    if !src.domain_strategy.is_empty() && src.domain_strategy != "AsIs" {
        warnings.push(format!(
            "domain_strategy = {:?} — DROP (FR-UI-131: мёртвое поле некора)",
            src.domain_strategy
        ));
    }

    // sniffing: 2 — DROP аудита → 1.
    r.sniffing_mode = src.sniffing_mode;
    if r.sniffing_mode == 2 {
        warnings.push("sniffing_mode = 2 не переносится (FR-UI-132: DROP) — установлен 1".into());
        r.sniffing_mode = 1;
    }

    // Списки: построчно, «#»-комментарии вырезаются.
    r.proxy_domain = split_lines(&src.proxy_domain);
    r.direct_domain = split_lines(&src.direct_domain);
    r.proxy_ip = split_lines(&src.proxy_ip);
    r.direct_ip = split_lines(&src.direct_ip);
    r.block_domain = split_lines(&src.block_domain);
    r.block_ip = split_lines(&src.block_ip);

    // custom → процессные правила / custom_rules.
    let (process, rest, custom_warns) = extract_custom_rules(&src.custom)?;
    warnings.extend(custom_warns);
    r.process_rules = process;
    r.custom_rules = rest;

    // DNS.
    let d = &mut out.dns;
    if src.use_dns_object {
        d.mode = "advanced".into();
        d.advanced_json = if src.dns_object.is_empty() {
            "{}".into()
        } else {
            src.dns_object.clone()
        };
        warnings.push("use_dns_object=true → dns.mode=advanced".into());
    } else {
        d.mode = "simple".into();
    }
    d.remote_dns = if src.remote_dns.is_empty() {
        "https://dns.google/dns-query".into() // дефолт RoutingBean
    } else {
        src.remote_dns.clone()
    };
    d.direct_dns = if src.direct_dns.is_empty() {
        "local".into()
    } else {
        src.direct_dns.clone()
    };
    d.remote_query_strategy = map_strategy(
        &src.remote_dns_strategy,
        &mut warnings,
        "remote_dns_strategy",
    );
    d.routing_enabled = src.dns_routing;
    d.underlying_dns = if src.underlying_dns.is_empty() {
        "local".into()
    } else {
        src.underlying_dns.clone()
    };
    if !src.direct_dns_strategy.is_empty() && src.direct_dns_strategy != "AsIs" {
        warnings.push(format!(
            "direct_dns_strategy = {:?} — DROP (FR-UI-148)",
            src.direct_dns_strategy
        ));
    }
    if !src.dns_final_out.is_empty() {
        warnings.push(format!(
            "dns_final_out = {:?} — DROP (FR-UI-148)",
            src.dns_final_out
        ));
    }

    out.validate()?;
    Ok((out, warnings))
}

/// enum v2ray → LAVRay; AsIs/"" → "".
fn map_strategy(v: &str, warnings: &mut Vec<String>, field: &str) -> String {
    match v {
        "" | "AsIs" => String::new(),
        "UseIPv4" => "ipv4_only".into(),
        "UseIPv6" => "ipv6_only".into(),
        "PreferIPv4" => "prefer_ipv4".into(),
        "PreferIPv6" => "prefer_ipv6".into(),
        other => {
            warnings.push(format!(
                "{field} = {other:?} — неизвестное значение, сброшено"
            ));
            String::new()
        }
    }
}

/// Построчно; «#»-комментарии и пустые строки вырезаются.
fn split_lines(s: &str) -> Vec<String> {
    s.replace("\r\n", "\n")
        .split('\n')
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}
