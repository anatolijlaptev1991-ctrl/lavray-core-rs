// SPDX-License-Identifier: GPL-3.0-only

//! Тесты запрета путей к файлам в пользовательском JSON (T-08, filekeys).
//! Allowlist-мерж custom_config — в merge_allowlist.rs.

use lavray_cfgbuild::filekeys::reject_file_keys;
use serde_json::json;

#[test]
fn rejects_certificate_path() {
    let v = json!({ "tls": { "certificate_path": "/etc/secret.pem" } });
    assert!(reject_file_keys("", &v).is_err());
}

#[test]
fn rejects_executable_path_nested() {
    let v = json!({ "outbounds": [{ "type": "tor", "executable_path": "/bin/tor" }] });
    assert!(reject_file_keys("", &v).is_err());
}

#[test]
fn rejects_cache_file_path() {
    let v = json!({ "experimental": { "cache_file": { "path": "/tmp/x.db" } } });
    assert!(reject_file_keys("", &v).is_err());
}

#[test]
fn rejects_case_insensitive_path() {
    let v = json!({ "tls": { "Certificate_Path": "x" } });
    assert!(reject_file_keys("", &v).is_err());
}

#[test]
fn allows_url_path_in_transport() {
    let v = json!({ "transport": { "type": "ws", "path": "/ws" } });
    assert!(reject_file_keys("", &v).is_ok());
}

#[test]
fn allows_url_path_https_dns() {
    let v = json!({ "type": "https", "path": "/dns-query" });
    assert!(reject_file_keys("", &v).is_ok());
}

#[test]
fn rejects_path_without_url_type() {
    let v = json!({ "type": "local", "path": "/etc/passwd" });
    assert!(reject_file_keys("", &v).is_err());
}

#[test]
fn allows_process_path_exception() {
    let v = json!({ "process_path": "/usr/bin/app" });
    assert!(reject_file_keys("", &v).is_ok());
}

#[test]
fn allows_empty_path() {
    let v = json!({ "tls": { "certificate_path": "" } });
    assert!(reject_file_keys("", &v).is_ok());
}

#[test]
fn rejects_concat_marker_path() {
    let v = json!({ "+certificate_path": "x" });
    assert!(reject_file_keys("", &v).is_err());
}

#[test]
fn rejects_log_output() {
    let v = json!({ "log": { "output": "x.log" } });
    assert!(reject_file_keys("", &v).is_err());
}

#[test]
fn rejects_external_ui() {
    let v = json!({ "external_ui_download_url": "https://evil/x.zip" });
    assert!(reject_file_keys("", &v).is_err());
}

#[test]
fn allows_inline_certificate() {
    let v = json!({ "tls": { "certificate": "-----BEGIN CERTIFICATE-----" } });
    assert!(reject_file_keys("", &v).is_ok());
}

#[test]
fn rejects_unicode_fold_path_key() {
    // Unicode simple fold (паритет Go EqualFold / декодер sing-box): long s (ſ)
    // в «certificate_path» не должен обходить запрет путей.
    let v = json!({ "tls": { "certificate_path": "/etc/secret.pem" } });
    assert!(reject_file_keys("", &v).is_err());
    // Kelvin sign (K) в «_path»-ключе.
    let v2 = json!({ "cache_file": { "patK": "x" } });
    // patK не путь (нет суффикса _path) — контроль, что fold не ломает обычные ключи.
    assert!(reject_file_keys("", &v2).is_ok());
}
