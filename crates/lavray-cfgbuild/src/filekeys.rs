// SPDX-License-Identifier: GPL-3.0-only

//! Запрет путей к файлам в пользовательском/импортированном JSON (порт Go
//! `cfgbuild/filekeys.go`, T-08/A1-01). Allowlist пускает поддеревья
//! route/dns/outbounds, но ключи-пути (certificate_path, executable_path,
//! cache_file.path, …) не должны попасть в конфиг ни при каком флаге.

use crate::error::{Error, Result};
use serde_json::Value;

const FILE_KEY_SUFFIXES: &[&str] = &[
    "_path",
    "_paths",
    "_file",
    "_files",
    "_dir",
    "_dirs",
    "_directory",
];
const FILE_KEY_EXCEPTIONS: &[&str] = &["process_path"];
const EXACT_FILE_KEYS: &[&str] = &["directory", "external_ui", "external_ui_download_url"];

/// Ключ без маркеров конкатенации ("+key"/"key+" → "key").
#[must_use]
pub fn merge_key_base(key: &str) -> String {
    let s = key.strip_prefix('+').unwrap_or(key);
    s.strip_suffix('+').unwrap_or(s).to_string()
}

/// Обойти JSON и вернуть ошибку на первом ключе с путём к файлу.
pub fn reject_file_keys(root: &str, v: &Value) -> Result<()> {
    walk_file_keys(root, &[], v)
}

fn walk_file_keys(trail: &str, stack: &[String], v: &Value) -> Result<()> {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                let base = merge_key_base(k);
                let child = &map[k];
                let key = if trail.is_empty() {
                    base.clone()
                } else {
                    format!("{trail}.{base}")
                };
                if is_file_key(stack, &base, map, child) {
                    let msg = format!("key {key:?} sets a file path; file paths are not allowed in custom config (put the contents inline, e.g. tls.certificate, or remove the key)");
                    return Err(Error::invalid(key, msg));
                }
                let mut next = stack.to_vec();
                next.push(base);
                walk_file_keys(&key, &next, child)?;
            }
        }
        Value::Array(arr) => {
            for (i, el) in arr.iter().enumerate() {
                walk_file_keys(&format!("{trail}[{i}]"), stack, el)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_file_key(
    stack: &[String],
    key: &str,
    obj: &serde_json::Map<String, Value>,
    val: &Value,
) -> bool {
    if !non_empty_stringish(val) {
        return false;
    }
    if eq_fold(key, "path") {
        return !is_url_path(stack, obj);
    }
    if eq_fold(key, "output") {
        return stack.last().is_some_and(|s| eq_fold(s, "log"));
    }
    if EXACT_FILE_KEYS.iter().any(|n| eq_fold(key, n)) {
        return true;
    }
    if FILE_KEY_EXCEPTIONS.iter().any(|n| eq_fold(key, n)) {
        return false;
    }
    FILE_KEY_SUFFIXES.iter().any(|s| has_fold_suffix(key, s))
}

fn is_url_path(stack: &[String], obj: &serde_json::Map<String, Value>) -> bool {
    if stack.last().is_some_and(|s| eq_fold(s, "transport")) {
        return true;
    }
    let mut typ = String::new();
    let mut count = 0;
    for (k, v) in obj {
        if eq_fold(&merge_key_base(k), "type") {
            count += 1;
            typ = v.as_str().unwrap_or("").to_string();
        }
    }
    count == 1 && matches!(typ.as_str(), "http" | "https" | "h3" | "ws" | "httpupgrade")
}

fn non_empty_stringish(v: &Value) -> bool {
    match v {
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => false,
    }
}

/// Регистронезависимое сравнение по Unicode simple fold (паритет Go
/// strings.EqualFold, как декодер sing-box): ſ→s, K→k и т.п. — чтобы
/// Unicode-эквиваленты ключей-путей не обходили запрет.
fn eq_fold(a: &str, b: &str) -> bool {
    let mut ai = a.chars().map(simple_fold);
    let mut bi = b.chars().map(simple_fold);
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) if x == y => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// Simple fold одного символа (1:1): long s → s, иначе lowercase.
fn simple_fold(c: char) -> char {
    if c == '\u{017F}' {
        's'
    } else {
        c.to_lowercase().next().unwrap_or(c)
    }
}

/// s оканчивается на suffix без учёта регистра (по символам).
fn has_fold_suffix(s: &str, suffix: &str) -> bool {
    let r: Vec<char> = s.chars().collect();
    let n = suffix.chars().count();
    if r.len() < n {
        return false;
    }
    let tail: String = r[r.len() - n..].iter().collect();
    eq_fold(&tail, suffix)
}
