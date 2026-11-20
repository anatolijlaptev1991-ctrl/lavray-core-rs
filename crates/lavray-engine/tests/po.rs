// SPDX-License-Identifier: GPL-3.0-only

//! Тесты моста «профиль → outbound»: hysteria2 и tuic конвертация.

use lavray_engine::profile_outbound::{ProfileOutbound, from_profile};

#[test]
fn hysteria2_profile_to_config() {
    let json = r#"{
        "type": "hysteria2",
        "name": "hy2",
        "address": "10.0.0.7",
        "port": 8443,
        "detail": {"password": "pw1"},
        "stream": {"security": "tls", "sni": "hy2.example", "allow_insecure": true}
    }"#;
    let p: lavray_model::profile::Profile = serde_json::from_str(json).expect("profile");
    let ProfileOutbound::Hysteria2(cfg) = from_profile(&p).expect("convert") else {
        panic!("expected Hysteria2 variant");
    };
    assert_eq!(cfg.server, "10.0.0.7");
    assert_eq!(cfg.server_port, 8443);
    assert_eq!(cfg.sni, "hy2.example");
    assert_eq!(cfg.password, "pw1");
    assert!(cfg.skip_verify);
}

#[test]
fn hysteria2_profile_defaults() {
    // без stream: sni = адрес, skip_verify = false
    let json = r#"{
        "type": "hysteria2",
        "name": "h",
        "address": "hy2.host",
        "port": 443,
        "detail": {"password": "p"}
    }"#;
    let p: lavray_model::profile::Profile = serde_json::from_str(json).expect("profile");
    let ProfileOutbound::Hysteria2(cfg) = from_profile(&p).expect("convert") else {
        panic!("expected Hysteria2 variant");
    };
    assert_eq!(cfg.sni, "hy2.host");
    assert!(!cfg.skip_verify);
    assert_eq!(cfg.rx_bps, 0);
}

#[test]
fn hysteria2_profile_without_detail_unsupported() {
    let json = r#"{"type": "hysteria2", "name": "h", "address": "a", "port": 1}"#;
    let p: lavray_model::profile::Profile = serde_json::from_str(json).expect("profile");
    let out = from_profile(&p).expect("convert");
    assert!(matches!(out, ProfileOutbound::Unsupported("hysteria2")));
}
