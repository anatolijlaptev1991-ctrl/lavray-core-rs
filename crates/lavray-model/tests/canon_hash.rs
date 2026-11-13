// SPDX-License-Identifier: GPL-3.0-only

//! Тесты волны 2b: канонический JSON, хэш-подтверждение custom-полей (T-08B).
//! Паритет Go model/canonjson.go, customhash.go. Dedup — в dedup.rs.

use lavray_model::{
    canonical_json, custom_confirmed, custom_fields_hash, has_custom_content, CustomDetail, Detail,
    Profile, ProfileType,
};

// ---- canonjson ----

#[test]
fn canon_sorts_keys_no_whitespace() {
    let c = canonical_json(r#"{ "b" : 1, "a" : 2 }"#).unwrap();
    assert_eq!(c, r#"{"a":2,"b":1}"#);
}

#[test]
fn canon_numbers_preserved_as_text() {
    // Большое число не округляется до float (паритет json.Number).
    let c = canonical_json(r#"{"n":123456789012345678901234567890}"#).unwrap();
    assert_eq!(c, r#"{"n":123456789012345678901234567890}"#);
}

#[test]
fn canon_empty_and_whitespace() {
    assert_eq!(canonical_json("").unwrap(), "");
    assert_eq!(canonical_json("   ").unwrap(), "");
}

#[test]
fn canon_duplicate_key_rejected() {
    assert!(canonical_json(r#"{"a":1,"a":2}"#).is_err());
}

#[test]
fn canon_trailing_data_rejected() {
    assert!(canonical_json(r#"{"a":1} garbage"#).is_err());
}

#[test]
fn canon_invalid_json_rejected() {
    assert!(canonical_json("{bad").is_err());
}

#[test]
fn canon_nested_sorted() {
    let c = canonical_json(r#"{"z":{"y":1,"x":2},"a":[3,1,2]}"#).unwrap();
    assert_eq!(c, r#"{"a":[3,1,2],"z":{"x":2,"y":1}}"#);
}

#[test]
fn canon_html_not_escaped() {
    let c = canonical_json(r#"{"s":"<a>&b"}"#).unwrap();
    assert_eq!(c, r#"{"s":"<a>&b"}"#);
}

#[test]
fn canon_too_large_rejected() {
    let big = format!("{{\"a\":\"{}\"}}", "x".repeat(2 << 20));
    assert!(canonical_json(&big).is_err());
}

// ---- customhash ----

fn profile_with_custom(outbound: &str, config: &str) -> Profile {
    Profile {
        custom_outbound_json: outbound.into(),
        custom_config_json: config.into(),
        ..Default::default()
    }
}

#[test]
fn hash_stable_for_same_content() {
    let p = profile_with_custom(r#"{"a":1}"#, "");
    let h1 = custom_fields_hash(&p).unwrap();
    let h2 = custom_fields_hash(&p).unwrap();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
}

#[test]
fn hash_key_order_independent() {
    let p1 = profile_with_custom(r#"{"a":1,"b":2}"#, "");
    let p2 = profile_with_custom(r#"{"b":2,"a":1}"#, "");
    assert_eq!(
        custom_fields_hash(&p1).unwrap(),
        custom_fields_hash(&p2).unwrap()
    );
}

#[test]
fn confirmation_via_hash_not_flag() {
    let mut p = profile_with_custom(r#"{"a":1}"#, "");
    let h = custom_fields_hash(&p).unwrap();
    p.custom_hash = h;
    assert!(custom_confirmed(&p));
    // Правка содержимого снимает подтверждение сама (без сброса флага).
    p.custom_outbound_json = r#"{"a":2}"#.into();
    assert!(!custom_confirmed(&p));
}

#[test]
fn forged_flag_without_hash_not_confirmed() {
    let mut p = profile_with_custom(r#"{"a":1}"#, "");
    p.custom_fields_confirmed = true; // клиент «выставил флаг»
    p.custom_hash = String::new(); // но хэша нет
    assert!(!custom_confirmed(&p));
}

#[test]
fn empty_content_not_confirmable() {
    let p = profile_with_custom("", "");
    assert!(!has_custom_content(&p));
    assert!(!custom_confirmed(&p));
}

#[test]
fn empty_object_is_no_content() {
    let p = profile_with_custom("{}", "");
    assert!(!has_custom_content(&p));
}

#[test]
fn invalid_json_is_content_but_not_hashable() {
    let p = profile_with_custom("{bad", "");
    assert!(has_custom_content(&p));
    assert!(custom_fields_hash(&p).is_err());
}

#[test]
fn internal_full_hashed() {
    let p = Profile {
        r#type: ProfileType::CustomConfig,
        detail: Some(Detail::Custom(CustomDetail {
            core: "internal-full".into(),
            full_config_json: r#"{"log":{"level":"info"}}"#.into(),
            ..Default::default()
        })),
        ..Default::default()
    };
    assert!(has_custom_content(&p));
    assert!(custom_fields_hash(&p).is_ok());
}
