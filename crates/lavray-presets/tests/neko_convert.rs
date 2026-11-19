// SPDX-License-Identifier: GPL-3.0-only

//! Тесты конвертера NekoRay → LAVRay (порт Go convert_test.go):
//! списки/«#»-комментарии, стратегии, DNS-объект, custom-правила
//! (*.exe → windows-only), DROP-поля → warnings, невалидный def_outbound.

use lavray_presets::{ConvertMeta, convert_neko_route, parse_neko_route};

fn meta() -> ConvertMeta {
    ConvertMeta {
        id: "custom:import".into(),
        name: "Route".into(),
    }
}

#[test]
fn minimal_route_defaults() {
    let src = parse_neko_route("{}").unwrap();
    let (p, w) = convert_neko_route(&src, &meta()).unwrap();
    assert_eq!(p.id, "custom:import");
    assert_eq!(p.routing.def_outbound, "proxy");
    assert_eq!(p.dns.mode, "simple");
    assert_eq!(p.dns.remote_dns, "https://dns.google/dns-query");
    assert_eq!(p.dns.direct_dns, "local");
    assert_eq!(p.dns.underlying_dns, "local");
    assert!(w.is_empty(), "{w:?}");
}

#[test]
fn lists_lines_and_comments() {
    let src = parse_neko_route(
        r#"{
        "direct_domain": "ya.ru # госкорпорация\n\nvk.ru\n# комментарий",
        "proxy_ip": "1.1.1.1\n2.2.2.2",
        "block_domain": "geosite:category-ads-all"
    }"#,
    )
    .unwrap();
    let (p, _) = convert_neko_route(&src, &meta()).unwrap();
    assert_eq!(
        p.routing.direct_domain,
        vec!["ya.ru".to_string(), "vk.ru".into()]
    );
    assert_eq!(p.routing.proxy_ip.len(), 2);
    assert_eq!(p.routing.block_domain.len(), 1);
}

#[test]
fn strategies_and_drops() {
    let src = parse_neko_route(
        r#"{
        "outbound_domain_strategy": "UseIPv4",
        "domain_strategy": "UseIPv6",
        "remote_dns_strategy": "PreferIPv6",
        "direct_dns_strategy": "UseIPv4",
        "dns_final_out": "proxy",
        "sniffing_mode": 2
    }"#,
    )
    .unwrap();
    let (p, w) = convert_neko_route(&src, &meta()).unwrap();
    assert_eq!(p.routing.outbound_domain_strategy, "ipv4_only");
    assert_eq!(p.dns.remote_query_strategy, "prefer_ipv6");
    assert_eq!(p.routing.sniffing_mode, 1);
    assert_eq!(w.len(), 4, "{w:?}"); // domain_strategy, direct_dns_strategy, dns_final_out, sniffing
}

#[test]
fn dns_object_advanced() {
    let src =
        parse_neko_route(r#"{"use_dns_object": true, "dns_object": "{\"servers\":[]}" }"#).unwrap();
    let (p, w) = convert_neko_route(&src, &meta()).unwrap();
    assert_eq!(p.dns.mode, "advanced");
    assert_eq!(p.dns.advanced_json, r#"{"servers":[]}"#);
    assert!(w.iter().any(|x| x.contains("advanced")));
}

#[test]
fn custom_process_rules_exe_and_posix() {
    let custom = serde_json::to_string(&serde_json::json!({
        "rules": [
            {"process_name": ["game.exe", "launcher.exe"], "outbound": "bypass"},
            {"process_name": "steam", "outbound": "proxy"},
            {"domain_suffix": ["corp.local"], "outbound": "direct"},
        ]
    }))
    .unwrap();
    let src_json = serde_json::to_string(&serde_json::json!({ "custom": custom })).unwrap();
    let src = parse_neko_route(&src_json).unwrap();
    let (p, _) = convert_neko_route(&src, &meta()).unwrap();
    assert_eq!(p.routing.process_rules.len(), 2, "windows + posix");
    let win = &p.routing.process_rules[0];
    assert_eq!(win.platforms, vec!["windows".to_string()]);
    assert_eq!(win.outbound, "direct");
    assert_eq!(win.process_names.len(), 2);
    let posix = &p.routing.process_rules[1];
    assert_eq!(posix.platforms, vec!["linux".to_string(), "macos".into()]);
    assert_eq!(posix.outbound, "proxy");
    // Непроцессное правило — в custom_rules строкой JSON.
    assert!(p.routing.custom_rules.contains("corp.local"));
}

#[test]
fn custom_bad_outbound_warns_and_proxies() {
    let src = parse_neko_route(
        r#"{"custom": "{\"rules\":[{\"process_name\":\"x\",\"outbound\":\"weird\"}]}" }"#,
    )
    .unwrap();
    let (p, w) = convert_neko_route(&src, &meta()).unwrap();
    assert_eq!(p.routing.process_rules[0].outbound, "proxy");
    assert!(w.iter().any(|x| x.contains("weird")));
}

#[test]
fn invalid_def_outbound_rejected() {
    let src = parse_neko_route(r#"{"def_outbound":"side"}"#).unwrap();
    assert!(convert_neko_route(&src, &meta()).is_err());
}

#[test]
fn unknown_strategy_resets_with_warning() {
    let src = parse_neko_route(r#"{"remote_dns_strategy":"Fastest"}"#).unwrap();
    let (p, w) = convert_neko_route(&src, &meta()).unwrap();
    assert_eq!(p.dns.remote_query_strategy, "");
    assert!(w.iter().any(|x| x.contains("remote_dns_strategy")));
}
