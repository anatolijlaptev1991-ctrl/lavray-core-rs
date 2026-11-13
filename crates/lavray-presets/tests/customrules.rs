// SPDX-License-Identifier: GPL-3.0-only

//! Тесты parse/normalize custom-правил (паритет Go presets/customrules.go).

use lavray_presets::{normalize_custom_rules, parse_custom_rules};

#[test]
fn empty_forms() {
    assert!(parse_custom_rules("").unwrap().is_empty());
    assert!(parse_custom_rules("   ").unwrap().is_empty());
    assert!(parse_custom_rules("null").unwrap().is_empty());
    assert!(parse_custom_rules("{}").unwrap().is_empty());
    assert_eq!(normalize_custom_rules("").unwrap(), "");
    assert_eq!(normalize_custom_rules("{}").unwrap(), "");
}

#[test]
fn array_of_objects() {
    let raw = r#"[{"outbound":"proxy","domain":["a.com"]},{"outbound":"block"}]"#;
    let rules = parse_custom_rules(raw).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["outbound"], "proxy");
}

#[test]
fn object_with_rules() {
    let raw = r#"{"rules":[{"outbound":"direct"}]}"#;
    let rules = parse_custom_rules(raw).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["outbound"], "direct");
}

#[test]
fn object_without_rules_rejected() {
    assert!(parse_custom_rules(r#"{"foo":1}"#).is_err());
}

#[test]
fn non_object_element_rejected() {
    assert!(parse_custom_rules(r#"[{"a":1},5]"#).is_err());
    assert!(parse_custom_rules(r#"["str"]"#).is_err());
}

#[test]
fn scalar_rejected() {
    assert!(parse_custom_rules("5").is_err());
    assert!(parse_custom_rules("\"str\"").is_err());
}

#[test]
fn rules_not_array_rejected() {
    assert!(parse_custom_rules(r#"{"rules":5}"#).is_err());
}

#[test]
fn invalid_json_rejected() {
    assert!(parse_custom_rules("[{").is_err());
}

#[test]
fn normalize_compact_array() {
    let raw = "[ { \"outbound\" : \"proxy\" } , { \"outbound\" : \"block\" } ]";
    let norm = normalize_custom_rules(raw).unwrap();
    assert_eq!(norm, r#"[{"outbound":"proxy"},{"outbound":"block"}]"#);
}

#[test]
fn size_limit_enforced() {
    let big = format!("[{{\"domain\":[\"{}\"]}}]", "a".repeat(300 << 10));
    assert!(parse_custom_rules(&big).is_err());
}
