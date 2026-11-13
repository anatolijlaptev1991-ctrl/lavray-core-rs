// SPDX-License-Identifier: GPL-3.0-only

//! Тесты волны 2b: каталог настроек + читатели (инвариант EverySettingHasReader),
//! geo-детекция (порт Go model/settings_readers_test.go, geo_test.go,
//! geo_false_positive_test.go).

use lavray_model::{
    backup_excluded, detect_geo, setting_descriptors, setting_readers, SETTING_UPDATE_ROOT_VERSION,
};

#[test]
fn every_setting_has_reader() {
    let readers = setting_readers();
    for d in setting_descriptors() {
        assert!(
            readers.contains_key(&d.key),
            "ключ {} без читателя (настройка-обманка)",
            d.key
        );
    }
}

#[test]
fn every_reader_has_descriptor() {
    let descriptors: Vec<String> = setting_descriptors()
        .iter()
        .map(|d| d.key.clone())
        .collect();
    for key in setting_readers().keys() {
        assert!(descriptors.contains(key), "читатель {key} без дескриптора");
    }
}

#[test]
fn descriptor_keys_unique() {
    let ds = setting_descriptors();
    let mut keys: Vec<&str> = ds.iter().map(|d| d.key.as_str()).collect();
    let n = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), n, "дубли ключей в каталоге");
}

#[test]
fn update_keys_internal_and_backup_excluded() {
    for d in setting_descriptors() {
        if d.key.starts_with("update.") && d.key != "update.channel" && d.key != "update.auto_check"
        {
            assert!(d.internal, "{} должен быть internal", d.key);
            assert!(d.backup_exclude, "{} должен быть backup_exclude", d.key);
            assert!(backup_excluded(&d.key));
        }
    }
    assert!(backup_excluded(SETTING_UPDATE_ROOT_VERSION));
    assert!(!backup_excluded("inbound.port"));
}

#[test]
fn defaults_present_for_key_settings() {
    let ds = setting_descriptors();
    let get = |k: &str| {
        ds.iter()
            .find(|d| d.key == k)
            .unwrap()
            .default_value
            .clone()
    };
    assert_eq!(get("inbound.port"), "2080");
    assert_eq!(get("routing.active_preset"), "\"lav-ru\"");
    assert_eq!(get("mux.concurrency"), "-1");
    assert_eq!(get("tun.mtu"), "9000");
}

// ---- geo ----

#[test]
fn geo_emoji_flag() {
    assert_eq!(detect_geo("🇷🇺 Россия", ""), "ru");
    assert_eq!(detect_geo("🇯🇵 Tokyo", ""), "jp");
    assert_eq!(detect_geo("🇳🇱 NL", ""), "nl");
}

#[test]
fn geo_explicit_code() {
    assert_eq!(detect_geo("[NL] Amsterdam", ""), "nl");
    assert_eq!(detect_geo("server_de_1", ""), "de");
    assert_eq!(detect_geo("node-jp-2", ""), "jp");
    assert_eq!(detect_geo("(US) New York", ""), "us");
}

#[test]
fn geo_alias_name() {
    assert_eq!(detect_geo("Germany Frankfurt", ""), "de");
    assert_eq!(detect_geo("Япония Токио", ""), "jp");
    assert_eq!(detect_geo("New Zealand Auckland", ""), "nz");
}

#[test]
fn geo_tld() {
    assert_eq!(detect_geo("server", "example.ru"), "ru");
    assert_eq!(detect_geo("server", "example.de"), "de");
    // Общие TLD не считаются страной.
    assert_eq!(detect_geo("server", "example.com"), "");
    assert_eq!(detect_geo("server", "example.io"), "");
}

#[test]
fn geo_unknown_empty() {
    assert_eq!(detect_geo("plain server", "example.com"), "");
}

// ---- ложные срабатывания (T-54, B2-21) ----

#[test]
fn geo_false_positive_fukuoka_not_gb() {
    // «Fukuoka» не должен давать uk → GB (короткий алиас целым словом).
    assert_ne!(detect_geo("Fukuoka", ""), "gb");
}

#[test]
fn geo_false_positive_busan_not_us() {
    // «Busan» не должен давать usa → US.
    assert_ne!(detect_geo("Busan", ""), "us");
}

#[test]
fn geo_false_positive_ws_not_samoa() {
    // «vless-ws-cdn» не должен давать ws → Самоа (тег протокола).
    assert_ne!(detect_geo("vless-ws-cdn", ""), "ws");
}

#[test]
fn geo_short_alias_whole_word() {
    // «usa1» совпадает (цифра не буква), «uk-2» совпадает.
    assert_eq!(detect_geo("usa1", ""), "us");
    assert_eq!(detect_geo("uk-2", ""), "gb");
}
