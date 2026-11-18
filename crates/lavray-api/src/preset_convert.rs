// SPDX-License-Identifier: GPL-3.0-only

//! Конвертация набора маршрутов: формат LAVRay (`lavray-presets`) ↔ контракт
//! `lavray.v1` (RoutingPreset, DnsSettings). Порт Go `api/preset_convert.go`.

use crate::preset_convert_dns::{
    default_dns, dns_block_from_proto, dns_block_to_proto, strategy_from_proto, strategy_to_proto,
};
use lavray_presets::{Preset, ProcessRule};
use lavray_proto::v1 as pb;

/// Значения enum-ов контракта (prost-числа): Outbound/DomainStrategy/SniffingMode.
mod code {
    pub const OUT_UNSPEC: i32 = 0;
    pub const OUT_PROXY: i32 = 1;
    pub const OUT_DIRECT: i32 = 2;
    pub const OUT_BLOCK: i32 = 3;
    pub const SNIFF_FOR_ROUTING: i32 = 1;
}

/// Исходящий → enum (тег "bypass" некора = DIRECT, контракт enum Outbound).
#[must_use]
pub fn outbound_to_proto(s: &str) -> i32 {
    match s {
        "proxy" => code::OUT_PROXY,
        "direct" | "bypass" => code::OUT_DIRECT,
        "block" => code::OUT_BLOCK,
        _ => code::OUT_UNSPEC,
    }
}

/// Enum → исходящий ("" = UNSPECIFIED).
#[must_use]
pub fn outbound_from_proto(v: i32) -> String {
    match v {
        code::OUT_PROXY => "proxy".into(),
        code::OUT_DIRECT => "direct".into(),
        code::OUT_BLOCK => "block".into(),
        _ => String::new(),
    }
}

/// Формат LAVRay → контракт. DisplayName: builtin — ключ локализации
/// `preset.<id>`, пользовательский — говорящее имя (вычисляет вызывающий).
#[must_use]
pub fn preset_to_proto(p: &Preset, display_name: &str) -> pb::RoutingPreset {
    let mut r = pb::RoutingPreset {
        id: p.id.clone(),
        display_name: display_name.to_string(),
        builtin: p.builtin,
        revision: p.revision.cast_signed(),
        proxy_domain: p.routing.proxy_domain.clone(),
        direct_domain: p.routing.direct_domain.clone(),
        block_domain: p.routing.block_domain.clone(),
        proxy_ip: p.routing.proxy_ip.clone(),
        direct_ip: p.routing.direct_ip.clone(),
        block_ip: p.routing.block_ip.clone(),
        default_outbound: outbound_to_proto(&p.routing.def_outbound),
        sniffing_mode: if p.routing.sniffing_mode == 1 {
            code::SNIFF_FOR_ROUTING
        } else {
            code::OUT_UNSPEC
        },
        outbound_domain_strategy: strategy_to_proto(&p.routing.outbound_domain_strategy),
        custom_rules_json: str_opt(&p.routing.custom_rules),
        dns: Some(dns_block_to_proto(&p.dns)),
        builtin_source_id: p.source_id.clone(),
        builtin_source_revision: p.source_revision.cast_signed(),
        source_updated: false,
        process_rules: p
            .routing
            .process_rules
            .iter()
            .map(|pr| pb::ProcessRule {
                process_names: pr.process_names.clone(),
                outbound: outbound_to_proto(&pr.outbound),
                platforms: pr.platforms.clone(),
            })
            .collect(),
    };
    if p.builtin {
        r.display_name = format!("preset.{}", p.id);
    }
    r
}

/// Контракт → формат LAVRay (проверки — отдельно, `prepare_user`). Источник
/// копии (builtin_source_*) из контракта не читается: его ведёт ядро.
#[must_use]
pub fn preset_from_proto(r: &pb::RoutingPreset) -> Preset {
    let mut p = Preset {
        schema: lavray_presets::SCHEMA_REF.into(),
        version: lavray_presets::SCHEMA_VERSION,
        id: r.id.clone(),
        builtin: false, // пользовательские пресеты из контракта никогда не builtin
        revision: r.revision.max(0).cast_unsigned(),
        name: lavray_presets::Localized::default(),
        ..Default::default()
    };
    p.name.insert("en", r.display_name.clone());
    let routing = &mut p.routing;
    routing.def_outbound = outbound_from_proto(r.default_outbound);
    if routing.def_outbound.is_empty() {
        routing.def_outbound = "direct".into();
    }
    routing.outbound_domain_strategy = strategy_from_proto(r.outbound_domain_strategy);
    routing.sniffing_mode = u32::from(r.sniffing_mode == code::SNIFF_FOR_ROUTING);
    routing.proxy_domain.clone_from(&r.proxy_domain);
    routing.direct_domain.clone_from(&r.direct_domain);
    routing.block_domain.clone_from(&r.block_domain);
    routing.proxy_ip.clone_from(&r.proxy_ip);
    routing.direct_ip.clone_from(&r.direct_ip);
    routing.block_ip.clone_from(&r.block_ip);
    routing.custom_rules = r.custom_rules_json.clone().unwrap_or_default();
    routing.process_rules = process_rules_from_proto(&r.process_rules);
    p.dns = r
        .dns
        .as_ref()
        .map_or_else(default_dns, dns_block_from_proto);
    p
}

fn process_rules_from_proto(rules: &[pb::ProcessRule]) -> Vec<ProcessRule> {
    rules
        .iter()
        .map(|pr| ProcessRule {
            platforms: pr.platforms.clone(),
            outbound: outbound_from_proto(pr.outbound),
            process_names: pr.process_names.clone(),
        })
        .collect()
}

fn str_opt(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}
