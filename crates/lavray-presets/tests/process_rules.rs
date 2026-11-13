// SPDX-License-Identifier: GPL-3.0-only

//! Тесты effective_process_rules (паритет Go presets/process_rules.go).

use lavray_presets::{effective_process_rules, Preset, ProcessRule, Routing};

fn preset_with(rules: Vec<ProcessRule>) -> Preset {
    Preset {
        routing: Routing {
            process_rules: rules,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn rule(platforms: &[&str], outbound: &str) -> ProcessRule {
    ProcessRule {
        platforms: platforms.iter().map(|s| (*s).to_string()).collect(),
        outbound: outbound.into(),
        process_names: vec!["app.exe".into()],
    }
}

#[test]
fn empty_platforms_applies_to_all() {
    let p = preset_with(vec![rule(&[], "proxy")]);
    let (out, warn) = effective_process_rules(&p, "windows", false);
    assert_eq!(out.len(), 1);
    assert_eq!(warn, Vec::<String>::new());
}

#[test]
fn platform_filter_windows() {
    let p = preset_with(vec![
        rule(&["windows"], "proxy"),
        rule(&["linux"], "direct"),
    ]);
    let (out, _) = effective_process_rules(&p, "windows", false);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].outbound, "proxy");
}

#[test]
fn darwin_maps_to_macos() {
    let p = preset_with(vec![rule(&["macos"], "proxy")]);
    let (out, _) = effective_process_rules(&p, "darwin", false);
    assert_eq!(out.len(), 1);
}

#[test]
fn openwrt_drops_all_with_warning() {
    let p = preset_with(vec![rule(&[], "proxy")]);
    let (out, warn) = effective_process_rules(&p, "linux", true);
    assert_eq!(out, Vec::<ProcessRule>::new());
    assert_eq!(warn.len(), 1);
    assert!(warn[0].contains("роутере"));
}

#[test]
fn unknown_platform_drops_with_warning() {
    let p = preset_with(vec![rule(&[], "proxy")]);
    let (out, warn) = effective_process_rules(&p, "freebsd", false);
    assert_eq!(out, Vec::<ProcessRule>::new());
    assert_eq!(warn.len(), 1);
}

#[test]
fn no_rules_no_warning() {
    let p = preset_with(vec![]);
    let (out, warn) = effective_process_rules(&p, "freebsd", false);
    assert_eq!(out, Vec::<ProcessRule>::new());
    assert_eq!(warn, Vec::<String>::new());
}
