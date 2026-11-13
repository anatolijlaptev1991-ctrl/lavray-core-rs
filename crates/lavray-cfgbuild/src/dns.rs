// SPDX-License-Identifier: GPL-3.0-only

//! DNS-секция из пресета (порт Go `cfgbuild/dns.go`): simple/advanced,
//! типизированные серверы sing-box 1.14, dns_routing-правила, fakeDNS (TUN).

use crate::error::{Error, Result};
use crate::route::{make_match_rule, RuleSetCollector};
use crate::settings::BuildSettings;
use crate::util::{obj, Obj};
use crate::BuildResult;
use lavray_presets::Preset;
use serde_json::{json, Value};

/// dns{} конфига. DNS-правила собирают rule-set ДО маршрутных (как оракул).
pub fn build_dns(
    preset: &Preset,
    st: &BuildSettings,
    res: &BuildResult,
    for_test: bool,
    rs: &mut RuleSetCollector,
) -> Result<Obj> {
    if preset.dns.mode == "advanced" {
        return advanced_dns(preset);
    }
    let mut dns_remote_list: Vec<String> = Vec::new();
    let mut dns_direct_list: Vec<String> = res.server_domains.clone();
    if preset.dns.routing_enabled && !for_test {
        dns_remote_list.extend(preset.routing.proxy_domain.iter().cloned());
        dns_direct_list.extend(preset.routing.direct_domain.iter().cloned());
    }

    let mut servers: Vec<Value> = Vec::new();
    let mut rules: Vec<Value> = Vec::new();

    if !for_test {
        let detour = if st.dns_remote_direct { "" } else { "proxy" };
        servers.push(Value::Object(make_dns_server(
            "dns-remote",
            &preset.dns.remote_dns,
            detour,
            true,
        )?));
    }
    servers.push(Value::Object(make_dns_server(
        "dns-direct",
        &preset.dns.direct_dns,
        "",
        true,
    )?));

    let fake_dns = st.tun.fake_dns && st.tun.enabled && !for_test;
    if fake_dns {
        servers.push(json!({
            "tag": "dns-fake", "type": "fakeip",
            "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"
        }));
    }

    let mut underlying = st.underlying_dns.trim().to_string();
    if underlying.is_empty() {
        underlying = preset.dns.underlying_dns.trim().to_string();
    }
    if underlying.is_empty() {
        underlying = "local".into();
    }
    servers.push(Value::Object(make_dns_server(
        "dns-local",
        &underlying,
        "",
        false,
    )?));

    let mut add_rule_dns = |list: &[String], server: &str, rules: &mut Vec<Value>| {
        let mut rule = make_match_rule(list, false, rs);
        if rule.is_empty() {
            return;
        }
        rule.insert("action".into(), json!("route"));
        rule.insert("server".into(), json!(server));
        rules.push(Value::Object(rule));
    };
    add_rule_dns(&dns_remote_list, "dns-remote", &mut rules);
    add_rule_dns(&dns_direct_list, "dns-direct", &mut rules);

    if !for_test {
        rules.push(json!({ "query_type": [32, 33], "action": "predefined", "rcode": 0 }));
        rules.push(json!({ "domain_suffix": [".lan"], "action": "predefined", "rcode": 0 }));
    }
    if fake_dns {
        rules.push(json!({ "inbound": "tun-in", "action": "route", "server": "dns-fake" }));
    }

    let mut dns = obj();
    dns.insert("servers".into(), Value::Array(servers));
    dns.insert("rules".into(), Value::Array(rules));
    if !preset.dns.remote_query_strategy.is_empty() {
        dns.insert("strategy".into(), json!(preset.dns.remote_query_strategy));
    }
    Ok(dns)
}

/// advanced (FR-UI-149): JSON dns «как есть» + наличие сервера dns-direct (LNB-08).
fn advanced_dns(preset: &Preset) -> Result<Obj> {
    let raw = preset.dns.advanced_json.trim();
    if raw.is_empty() {
        return Err(Error::invalid(
            "preset.dns.advanced_json",
            "dns.mode=advanced requires advanced_json",
        ));
    }
    let dns: Obj = serde_json::from_str(raw)
        .map_err(|e| Error::invalid("preset.dns.advanced_json", format!("invalid JSON: {e}")))?;
    let has_direct = dns
        .get("servers")
        .and_then(Value::as_array)
        .is_some_and(|servers| {
            servers
                .iter()
                .any(|s| s.get("tag").and_then(Value::as_str) == Some("dns-direct"))
        });
    if !has_direct {
        return Err(Error::invalid(
            "preset.dns.advanced_json",
            "advanced dns object must define a server tagged \"dns-direct\" (route.default_domain_resolver, LNB-08)",
        ));
    }
    Ok(dns)
}

pub use crate::dns_server::make_dns_server;
