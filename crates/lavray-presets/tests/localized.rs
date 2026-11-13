// SPDX-License-Identifier: GPL-3.0-only

//! Тесты Localized: канонический порядок ключей при маршале (детерминизм golden).

use lavray_presets::Localized;

#[test]
fn canonical_order_ru_zh_en_es_de() {
    let mut l = Localized::new();
    // Вставляем в обратном порядке — маршал должен дать канонический.
    l.insert("de", "D");
    l.insert("es", "E");
    l.insert("en", "N");
    l.insert("zh", "Z");
    l.insert("ru", "R");
    let json = serde_json::to_string(&l).unwrap();
    assert_eq!(json, r#"{"ru":"R","zh":"Z","en":"N","es":"E","de":"D"}"#);
}

#[test]
fn extra_langs_alphabetical_after_canonical() {
    let mut l = Localized::new();
    l.insert("fr", "F");
    l.insert("ru", "R");
    l.insert("ar", "A");
    l.insert("en", "N");
    let json = serde_json::to_string(&l).unwrap();
    // ru, en (канонические), затем ar, fr (алфавит).
    assert_eq!(json, r#"{"ru":"R","en":"N","ar":"A","fr":"F"}"#);
}

#[test]
fn empty_is_empty_object() {
    let l = Localized::new();
    assert_eq!(serde_json::to_string(&l).unwrap(), "{}");
    assert_eq!(l, Localized::new());
}

#[test]
fn round_trip_preserves_values() {
    let mut l = Localized::new();
    l.insert("ru", "Русский");
    l.insert("en", "English");
    let json = serde_json::to_string(&l).unwrap();
    let back: Localized = serde_json::from_str(&json).unwrap();
    assert_eq!(l, back);
    assert_eq!(back.get("ru"), Some("Русский"));
}

#[test]
fn deserialize_any_order() {
    let l: Localized = serde_json::from_str(r#"{"de":"D","ru":"R"}"#).unwrap();
    assert_eq!(l.len(), 2);
    assert_eq!(l.get("ru"), Some("R"));
    assert_eq!(l.get("de"), Some("D"));
}

#[test]
fn marshal_is_deterministic() {
    let mut l = Localized::new();
    l.insert("zh", "Z");
    l.insert("ru", "R");
    let a = serde_json::to_string(&l).unwrap();
    let b = serde_json::to_string(&l).unwrap();
    assert_eq!(a, b);
}

#[test]
fn get_missing_is_none() {
    let l = Localized::new();
    assert_eq!(l.get("ru"), None);
}
