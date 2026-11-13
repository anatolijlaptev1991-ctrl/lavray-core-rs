// SPDX-License-Identifier: GPL-3.0-only

//! Тесты валидации пресета (SCHEMA §4) — явные и неявные сценарии ошибок.

use lavray_presets::{load_preset, DnsBlock, Localized, Preset, ProcessRule, Routing};

/// Минимальный валидный пресет для мутаций в тестах.
fn valid() -> Preset {
    let mut p = Preset {
        schema: "preset.schema.v1.json".into(),
        version: 1,
        revision: 1,
        id: "test".into(),
        builtin: false,
        name: Localized::default(),
        description: Localized::default(),
        maintainer_notes: String::new(),
        routing: Routing {
            def_outbound: "proxy".into(),
            ..Default::default()
        },
        dns: DnsBlock {
            mode: "simple".into(),
            ..Default::default()
        },
        source_id: String::new(),
        source_revision: 0,
    };
    p.name.insert("ru", "Тест");
    p
}

#[test]
fn valid_preset_passes() {
    assert!(valid().validate().is_ok());
}

#[test]
fn version_zero_rejected() {
    let mut p = valid();
    p.version = 0;
    assert!(p.validate().unwrap_err().0.contains("version"));
}

#[test]
fn version_above_schema_rejected() {
    let mut p = valid();
    p.version = 2;
    assert!(p.validate().unwrap_err().0.contains("version"));
}

#[test]
fn empty_id_rejected() {
    let mut p = valid();
    p.id = String::new();
    assert!(p.validate().unwrap_err().0.contains("id"));
}

#[test]
fn revision_above_max_rejected() {
    let mut p = valid();
    p.revision = 1_000_000_001;
    assert!(p.validate().unwrap_err().0.contains("revision"));
}

#[test]
fn empty_name_rejected() {
    let mut p = valid();
    p.name = Localized::default();
    assert!(p.validate().unwrap_err().0.contains("name"));
}

#[test]
fn bad_def_outbound_rejected() {
    let mut p = valid();
    p.routing.def_outbound = "invalid".into();
    assert!(p.validate().unwrap_err().0.contains("def_outbound"));
}

#[test]
fn bad_domain_strategy_rejected() {
    let mut p = valid();
    p.routing.outbound_domain_strategy = "ipv9_only".into();
    assert!(p
        .validate()
        .unwrap_err()
        .0
        .contains("outbound_domain_strategy"));
}

#[test]
fn sniffing_mode_2_rejected() {
    let mut p = valid();
    p.routing.sniffing_mode = 2;
    assert!(p.validate().unwrap_err().0.contains("sniffing_mode"));
}

#[test]
fn geoip_in_domain_field_rejected() {
    let mut p = valid();
    p.routing.proxy_domain = vec!["geoip:ru".into()];
    assert!(p.validate().unwrap_err().0.contains("geoip"));
}

#[test]
fn geosite_in_ip_field_rejected() {
    let mut p = valid();
    p.routing.proxy_ip = vec!["geosite:google".into()];
    assert!(p.validate().unwrap_err().0.contains("geosite"));
}

#[test]
fn domain_prefix_in_ip_field_rejected() {
    let mut p = valid();
    p.routing.direct_ip = vec!["domain:example.com".into()];
    assert!(p.validate().unwrap_err().0.contains("доменные префиксы"));
}

#[test]
fn empty_prefix_value_rejected() {
    let mut p = valid();
    p.routing.proxy_domain = vec!["domain:".into()];
    assert!(p
        .validate()
        .unwrap_err()
        .0
        .contains("пустое значение после префикса"));
}

#[test]
fn whitespace_in_list_entry_rejected() {
    let mut p = valid();
    p.routing.proxy_domain = vec!["domain:bad name".into()];
    assert!(p.validate().unwrap_err().0.contains("пробелы"));
}

#[test]
fn bare_domain_in_domain_field_ok() {
    let mut p = valid();
    p.routing.proxy_domain = vec!["example.com".into()];
    assert!(p.validate().is_ok());
}

#[test]
fn cidr_in_ip_field_ok() {
    let mut p = valid();
    p.routing.proxy_ip = vec!["10.0.0.0/8".into(), "192.168.1.1".into()];
    assert!(p.validate().is_ok());
}

#[test]
fn non_ip_in_ip_field_rejected() {
    let mut p = valid();
    p.routing.proxy_ip = vec!["not-an-ip".into()];
    assert!(p.validate().unwrap_err().0.contains("CIDR"));
}

#[test]
fn process_rule_path_injection_rejected() {
    let mut p = valid();
    p.routing.process_rules = vec![ProcessRule {
        platforms: vec![],
        outbound: "direct".into(),
        process_names: vec!["../evil.exe".into()],
    }];
    assert!(p.validate().unwrap_err().0.contains("без пути"));
}

#[test]
fn process_rule_slash_rejected() {
    let mut p = valid();
    p.routing.process_rules = vec![ProcessRule {
        platforms: vec![],
        outbound: "direct".into(),
        process_names: vec!["dir/app.exe".into()],
    }];
    assert!(p.validate().unwrap_err().0.contains("без пути"));
}

#[test]
fn process_rule_unknown_platform_rejected() {
    let mut p = valid();
    p.routing.process_rules = vec![ProcessRule {
        platforms: vec!["plan9".into()],
        outbound: "direct".into(),
        process_names: vec!["app.exe".into()],
    }];
    assert!(p
        .validate()
        .unwrap_err()
        .0
        .contains("неизвестная платформа"));
}

#[test]
fn process_rule_empty_names_rejected() {
    let mut p = valid();
    p.routing.process_rules = vec![ProcessRule {
        platforms: vec![],
        outbound: "direct".into(),
        process_names: vec![],
    }];
    assert!(p.validate().unwrap_err().0.contains("process_names: пуст"));
}

#[test]
fn valid_process_rule_ok() {
    let mut p = valid();
    p.routing.process_rules = vec![ProcessRule {
        platforms: vec!["windows".into()],
        outbound: "direct".into(),
        process_names: vec!["game.exe".into()],
    }];
    assert!(p.validate().is_ok());
}

#[test]
fn custom_rules_invalid_json_rejected() {
    let mut p = valid();
    p.routing.custom_rules = "{not json".into();
    assert!(p.validate().unwrap_err().0.contains("custom_rules"));
}

#[test]
fn custom_rules_valid_json_ok() {
    let mut p = valid();
    p.routing.custom_rules = "[]".into();
    assert!(p.validate().is_ok());
}

#[test]
fn dns_bad_mode_rejected() {
    let mut p = valid();
    p.dns.mode = "turbo".into();
    assert!(p.validate().unwrap_err().0.contains("dns.mode"));
}

#[test]
fn dns_advanced_requires_valid_json() {
    let mut p = valid();
    p.dns.mode = "advanced".into();
    p.dns.advanced_json = String::new();
    assert!(p.validate().unwrap_err().0.contains("advanced_json"));
}

#[test]
fn load_preset_invalid_json() {
    assert!(load_preset("{broken").is_err());
}

#[test]
fn load_preset_validates() {
    let bad = r#"{"version":1,"id":"","name":{"ru":"x"},"routing":{"def_outbound":"proxy"},"dns":{"mode":"simple"}}"#;
    assert!(load_preset(bad).is_err());
}
