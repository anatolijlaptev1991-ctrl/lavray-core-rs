// SPDX-License-Identifier: GPL-3.0-only

//! DnsSettings ↔ DnsBlock (порт Go preset_convert.go, вынесено трещоткой
//! размеров). Пустые строки прото → "" модели, стратегия UNSPECIFIED → "".

use lavray_presets::DnsBlock;
use lavray_proto::v1 as pb;

fn str_opt(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// Значения enum-ов контракта (prost-числа).
mod code {
    /// MODE_ADVANCED у DnsSettings.Mode.
    pub const DNS_MODE_ADVANCED: i32 = 2;
}

pub fn strategy_to_proto(s: &str) -> i32 {
    match s {
        "prefer_ipv4" => pb::DomainStrategy::PreferIpv4 as i32,
        "prefer_ipv6" => pb::DomainStrategy::PreferIpv6 as i32,
        "ipv4_only" => pb::DomainStrategy::Ipv4Only as i32,
        "ipv6_only" => pb::DomainStrategy::Ipv6Only as i32,
        _ => 0,
    }
}

pub fn strategy_from_proto(v: i32) -> String {
    match pb::DomainStrategy::try_from(v) {
        Ok(pb::DomainStrategy::PreferIpv4) => "prefer_ipv4".into(),
        Ok(pb::DomainStrategy::PreferIpv6) => "prefer_ipv6".into(),
        Ok(pb::DomainStrategy::Ipv4Only) => "ipv4_only".into(),
        Ok(pb::DomainStrategy::Ipv6Only) => "ipv6_only".into(),
        _ => String::new(),
    }
}

/// ДНС-блок по умолчанию контракта (Go presetFromProto: DNS не прислан).
#[must_use]
pub(crate) fn default_dns() -> DnsBlock {
    DnsBlock {
        mode: "simple".into(),
        remote_dns: "https://dns.google/dns-query".into(),
        direct_dns: "local".into(),
        routing_enabled: true,
        ..Default::default()
    }
}

pub fn dns_block_to_proto(d: &DnsBlock) -> pb::DnsSettings {
    pb::DnsSettings {
        mode: if d.mode == "advanced" {
            code::DNS_MODE_ADVANCED
        } else {
            pb::dns_settings::Mode::Simple as i32
        },
        remote_dns: str_opt(&d.remote_dns),
        remote_query_strategy: if d.remote_query_strategy.is_empty() {
            None
        } else {
            Some(strategy_to_proto(&d.remote_query_strategy))
        },
        direct_dns: str_opt(&d.direct_dns),
        routing_enabled: d.routing_enabled,
        advanced_json: str_opt(&d.advanced_json),
        underlying_dns: str_opt(&d.underlying_dns),
        ..Default::default()
    }
}

pub fn dns_block_from_proto(d: &pb::DnsSettings) -> DnsBlock {
    DnsBlock {
        mode: if d.mode == code::DNS_MODE_ADVANCED {
            "advanced".into()
        } else {
            "simple".into()
        },
        remote_dns: d.remote_dns.clone().unwrap_or_default(),
        remote_query_strategy: d
            .remote_query_strategy
            .and_then(|v| {
                let s = strategy_from_proto(v);
                (!s.is_empty()).then_some(s)
            })
            .unwrap_or_default(),
        direct_dns: d.direct_dns.clone().unwrap_or_default(),
        routing_enabled: d.routing_enabled,
        advanced_json: d.advanced_json.clone().unwrap_or_default(),
        underlying_dns: d.underlying_dns.clone().unwrap_or_default(),
    }
}
