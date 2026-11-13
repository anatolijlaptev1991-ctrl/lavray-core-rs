// SPDX-License-Identifier: GPL-3.0-only

//! Тесты allowlist-мержа custom_config (LNB-25, §3.1.1): корневые секции,
//! log.level, experimental.cache_file, outbounds по тегу, конкатенация.

use lavray_cfgbuild::merge_custom_config;
use lavray_cfgbuild::util::Obj;
use serde_json::json;

fn cfg_with_outbound(tag: &str) -> Obj {
    let mut cfg = Obj::new();
    cfg.insert("outbounds".into(), json!([{ "type": "socks", "tag": tag }]));
    cfg
}

#[test]
fn merge_empty_noop() {
    let mut cfg = cfg_with_outbound("proxy");
    assert!(merge_custom_config(&mut cfg, "", &["proxy".into()]).is_ok());
    assert!(merge_custom_config(&mut cfg, "{}", &["proxy".into()]).is_ok());
}

#[test]
fn merge_rejects_inbounds_root() {
    let mut cfg = cfg_with_outbound("proxy");
    assert!(merge_custom_config(&mut cfg, r#"{"inbounds":[]}"#, &["proxy".into()]).is_err());
}

#[test]
fn merge_rejects_log_output() {
    let mut cfg = cfg_with_outbound("proxy");
    assert!(
        merge_custom_config(&mut cfg, r#"{"log":{"output":"x.log"}}"#, &["proxy".into()]).is_err()
    );
}

#[test]
fn merge_allows_log_level() {
    let mut cfg = cfg_with_outbound("proxy");
    cfg.insert("log".into(), json!({ "level": "info" }));
    merge_custom_config(&mut cfg, r#"{"log":{"level":"debug"}}"#, &["proxy".into()]).unwrap();
    assert_eq!(cfg["log"]["level"], "debug");
}

#[test]
fn merge_rejects_clash_api() {
    let mut cfg = cfg_with_outbound("proxy");
    let src = r#"{"experimental":{"clash_api":{"external_ui":"x"}}}"#;
    assert!(merge_custom_config(&mut cfg, src, &["proxy".into()]).is_err());
}

#[test]
fn merge_rejects_cache_file_path_field() {
    let mut cfg = cfg_with_outbound("proxy");
    let src = r#"{"experimental":{"cache_file":{"path":"x"}}}"#;
    assert!(merge_custom_config(&mut cfg, src, &["proxy".into()]).is_err());
}

#[test]
fn merge_allows_cache_file_enabled() {
    let mut cfg = cfg_with_outbound("proxy");
    let src = r#"{"experimental":{"cache_file":{"enabled":true}}}"#;
    merge_custom_config(&mut cfg, src, &["proxy".into()]).unwrap();
    assert_eq!(cfg["experimental"]["cache_file"]["enabled"], true);
}

#[test]
fn merge_outbounds_foreign_tag_rejected() {
    let mut cfg = cfg_with_outbound("proxy");
    let src = r#"{"outbounds":[{"tag":"other","server":"evil"}]}"#;
    assert!(merge_custom_config(&mut cfg, src, &["proxy".into()]).is_err());
}

#[test]
fn merge_outbounds_own_tag_merged() {
    let mut cfg = cfg_with_outbound("proxy");
    let src = r#"{"outbounds":[{"tag":"proxy","server":"1.2.3.4"}]}"#;
    merge_custom_config(&mut cfg, src, &["proxy".into()]).unwrap();
    assert_eq!(cfg["outbounds"][0]["server"], "1.2.3.4");
}

#[test]
fn merge_route_concat_rules() {
    let mut cfg = cfg_with_outbound("proxy");
    cfg.insert(
        "route".into(),
        json!({ "rules": [{ "outbound": "block" }] }),
    );
    let src = r#"{"route":{"+rules":[{"outbound":"proxy"}]}}"#;
    merge_custom_config(&mut cfg, src, &["proxy".into()]).unwrap();
    let rules = cfg["route"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["outbound"], "proxy"); // src ++ dst
}

#[test]
fn merge_rejects_file_key_in_route() {
    let mut cfg = cfg_with_outbound("proxy");
    let src = r#"{"route":{"rule_set":[{"path":"evil.srs"}]}}"#;
    assert!(merge_custom_config(&mut cfg, src, &["proxy".into()]).is_err());
}

#[test]
fn merge_concat_marker_non_array_rejected() {
    let mut cfg = cfg_with_outbound("proxy");
    assert!(merge_custom_config(&mut cfg, r#"{"+route":5}"#, &["proxy".into()]).is_err());
}

#[test]
fn merge_route_non_object_rejected() {
    let mut cfg = cfg_with_outbound("proxy");
    assert!(merge_custom_config(&mut cfg, r#"{"route":5}"#, &["proxy".into()]).is_err());
}

#[test]
fn merge_invalid_json_rejected() {
    let mut cfg = cfg_with_outbound("proxy");
    assert!(merge_custom_config(&mut cfg, "{bad", &["proxy".into()]).is_err());
}

#[test]
fn merge_dns_file_key_rejected() {
    let mut cfg = cfg_with_outbound("proxy");
    let src = r#"{"dns":{"servers":[{"certificate_path":"x"}]}}"#;
    assert!(merge_custom_config(&mut cfg, src, &["proxy".into()]).is_err());
}
