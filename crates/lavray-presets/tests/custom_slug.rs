// SPDX-License-Identifier: GPL-3.0-only

//! Тесты slug/mint_id/new_custom_from/prepare_user (паритет Go presets
//! slug_test.go, custom_test.go, limits_test.go).

use lavray_presets::{mint_id, new_custom_from, prepare_user, slugify, Preset, Routing};

#[test]
fn slug_latin_and_cyrillic() {
    assert_eq!(slugify("My Cool Set"), "my-cool-set");
    assert_eq!(slugify("Мой набор"), "moy-nabor");
    assert_eq!(slugify("Ёжик в тумане"), "ezhik-v-tumane");
    assert_eq!(slugify("Japan 日本"), "japan");
    assert_eq!(slugify("日本語"), "set", "не пригодных символов → set");
}

#[test]
fn slug_no_double_or_edge_dashes() {
    assert_eq!(slugify("a--b"), "a-b");
    assert_eq!(slugify("  a  b  "), "a-b");
    assert_eq!(slugify("---x---"), "x");
}

#[test]
fn slug_max_48() {
    let long = "x".repeat(100);
    let s = slugify(&long);
    assert_eq!(s.len(), 48);
}

#[test]
fn slug_empty_name_fallback() {
    assert_eq!(slugify(""), "set");
}

#[test]
fn mint_free_id() {
    let taken = |_id: &str| false;
    assert_eq!(mint_id("My Set", &taken), "custom:my-set");
}

#[test]
fn mint_collision_adds_suffix() {
    let taken = |id: &str| id == "custom:my-set";
    assert_eq!(mint_id("My Set", &taken), "custom:my-set-2");
}

#[test]
fn mint_uses_first_hole() {
    let taken = |id: &str| matches!(id, "custom:my-set" | "custom:my-set-2");
    assert_eq!(mint_id("My Set", &taken), "custom:my-set-3");
}

#[test]
fn mint_builtin_id_reserved() {
    let taken = |id: &str| id == "custom:lav-ru" || id == "lav-ru";
    assert_eq!(mint_id("lav-ru", &taken), "custom:lav-ru-2");
}

// ---- new_custom_from ----

fn base_builtin() -> Preset {
    Preset {
        id: "lav-ru".into(),
        revision: 3,
        builtin: true,
        ..Default::default()
    }
}

#[test]
fn custom_from_builtin_tracks_source() {
    let c = new_custom_from(&base_builtin(), "custom:copy");
    assert_eq!(c.id, "custom:copy");
    assert!(!c.builtin);
    assert_eq!(c.revision, 1);
    assert_eq!(c.source_id, "lav-ru");
    assert_eq!(c.source_revision, 3);
    assert_eq!(c.schema, "preset.schema.v1.json");
}

#[test]
fn custom_from_user_keeps_own_source() {
    let src = Preset {
        id: "custom:orig".into(),
        builtin: false,
        source_id: "lav-ru".into(),
        source_revision: 2,
        ..Default::default()
    };
    let c = new_custom_from(&src, "custom:copy");
    // Копия копии остаётся сбрасываемой на встроенный источник.
    assert_eq!(c.source_id, "lav-ru");
    assert_eq!(c.source_revision, 2);
}

// ---- prepare_user ----

#[test]
fn prepare_normalizes_custom_rules() {
    // Реалистичный путь UI: «Сохранить как» от встроенного набора.
    let base = lavray_presets::builtin_presets().unwrap();
    let mut p = base.iter().find(|b| b.id == "lav-ru").unwrap().clone();
    p.id = "custom:test".into();
    p.revision = 1;
    p.builtin = false;
    p.routing.custom_rules = "[ { \"outbound\" : \"proxy\" } ]".into();
    prepare_user(&mut p).unwrap();
    assert_eq!(p.routing.custom_rules, r#"[{"outbound":"proxy"}]"#);
}

#[test]
fn prepare_empty_name_rejected() {
    let mut p = Preset::default();
    p.name.insert("en", "   ");
    assert!(prepare_user(&mut p).is_err());
}

#[test]
fn prepare_name_too_long_rejected() {
    let mut p = Preset::default();
    p.name.insert("en", "x".repeat(100));
    assert!(prepare_user(&mut p).is_err());
}

#[test]
fn prepare_list_over_limit_rejected() {
    let mut p = Preset::default();
    p.name.insert("en", "S");
    p.routing.proxy_domain = (0..10_001).map(|i| format!("d{i}.com")).collect();
    assert!(prepare_user(&mut p).is_err());
}

#[test]
fn prepare_invalid_routing_rejected() {
    let mut p = Preset::default();
    p.name.insert("en", "S");
    p.routing = Routing {
        def_outbound: "bogus".into(),
        ..Default::default()
    };
    assert!(prepare_user(&mut p).is_err());
}
