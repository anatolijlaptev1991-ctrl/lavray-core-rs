// SPDX-License-Identifier: GPL-3.0-only

//! Unit-тесты cfgbuild: DNS-серверы, порты hysteria2, loglevel, MergeJSON.
//! Валидация звена и ошибки сборки — в validate_tests.rs.

use lavray_cfgbuild::dns::make_dns_server;
use lavray_cfgbuild::hy2ports::hysteria2_server_ports;
use lavray_cfgbuild::merge::merge_json;
use lavray_cfgbuild::util::{normalize_log_level, Obj};
use serde_json::json;

// ---- make_dns_server ----

#[test]
fn dns_local() {
    // Go local-ветка: early-return без domain_resolver (резолвер не нужен).
    let s = make_dns_server("dns-direct", "local", "", true).unwrap();
    assert_eq!(s["type"], "local");
    assert!(s.get("domain_resolver").is_none());
    assert!(s.get("detour").is_none());
}

#[test]
fn dns_https_path_and_resolver() {
    let s = make_dns_server("dns-remote", "https://dns.google/dns-query", "proxy", true).unwrap();
    assert_eq!(s["type"], "https");
    assert_eq!(s["server"], "dns.google");
    assert_eq!(s["path"], "/dns-query");
    assert_eq!(s["detour"], "proxy");
}

#[test]
fn dns_udp_default_with_port() {
    let s = make_dns_server("t", "1.1.1.1:53", "", false).unwrap();
    assert_eq!(s["type"], "udp");
    assert_eq!(s["server"], "1.1.1.1");
    assert_eq!(s["server_port"], 53);
}

#[test]
fn dns_ipv6_bracket_port() {
    let s = make_dns_server("t", "[2001:db8::1]:5353", "", false).unwrap();
    assert_eq!(s["server"], "2001:db8::1");
    assert_eq!(s["server_port"], 5353);
}

#[test]
fn dns_detour_direct_omitted() {
    // Фильтрация detour="direct" — в общей ветке (не local): sing-box 1.14
    // отвергает detour на прямой outbound.
    let s = make_dns_server("t", "1.1.1.1", "direct", false).unwrap();
    assert!(s.get("detour").is_none());
}

#[test]
fn dns_local_detour_kept() {
    // local-ветка ставит detour даже "direct" (паритет Go early-return).
    let s = make_dns_server("t", "local", "direct", false).unwrap();
    assert_eq!(s["detour"], "direct");
}

#[test]
fn dns_empty_host_rejected() {
    assert!(make_dns_server("t", "https://", "", false).is_err());
}

#[test]
fn dns_empty_address_defaults_local() {
    let s = make_dns_server("t", "", "", false).unwrap();
    assert_eq!(s["type"], "local");
}

// ---- hysteria2 ports ----

#[test]
fn ports_single_and_ranges() {
    assert_eq!(hysteria2_server_ports("8443").unwrap(), vec!["8443:8443"]);
    assert_eq!(
        hysteria2_server_ports("1000:2000").unwrap(),
        vec!["1000:2000"]
    );
    assert_eq!(
        hysteria2_server_ports("1000-2000").unwrap(),
        vec!["1000:2000"]
    );
    assert_eq!(
        hysteria2_server_ports("1000:2000,3000:4000").unwrap(),
        vec!["1000:2000", "3000:4000"]
    );
}

#[test]
fn ports_empty_ok() {
    assert!(hysteria2_server_ports("").unwrap().is_empty());
    assert!(hysteria2_server_ports("  ").unwrap().is_empty());
}

#[test]
fn ports_invalid_rejected() {
    assert!(hysteria2_server_ports("abc").is_err());
    assert!(hysteria2_server_ports("0").is_err());
    assert!(hysteria2_server_ports("70000").is_err());
    assert!(hysteria2_server_ports("2000:1000").is_err());
    assert!(hysteria2_server_ports("1000,,2000").is_err());
    assert!(hysteria2_server_ports("-5").is_err());
}

// ---- log level ----

#[test]
fn log_level_normalize() {
    assert_eq!(normalize_log_level("DEBUG"), "debug");
    assert_eq!(normalize_log_level("  warn "), "warn");
    assert_eq!(normalize_log_level("bogus"), "info");
    assert_eq!(normalize_log_level(""), "info");
}

// ---- MergeJSON ----

#[test]
fn merge_recursive_object() {
    let mut dst: Obj = serde_json::from_value(json!({ "a": { "x": 1, "y": 2 } })).unwrap();
    let src: Obj = serde_json::from_value(json!({ "a": { "y": 3, "z": 4 } })).unwrap();
    merge_json(&mut dst, &src);
    assert_eq!(dst["a"]["x"], 1);
    assert_eq!(dst["a"]["y"], 3);
    assert_eq!(dst["a"]["z"], 4);
}

#[test]
fn merge_plus_prefix_prepends_src() {
    let mut dst: Obj = serde_json::from_value(json!({ "rules": [3] })).unwrap();
    let src: Obj = serde_json::from_value(json!({ "+rules": [1, 2] })).unwrap();
    merge_json(&mut dst, &src);
    assert_eq!(dst["rules"], json!([1, 2, 3]));
}

#[test]
fn merge_plus_suffix_appends_src() {
    let mut dst: Obj = serde_json::from_value(json!({ "rules": [1] })).unwrap();
    let src: Obj = serde_json::from_value(json!({ "rules+": [2, 3] })).unwrap();
    merge_json(&mut dst, &src);
    assert_eq!(dst["rules"], json!([1, 2, 3]));
}
