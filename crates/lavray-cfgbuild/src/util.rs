// SPDX-License-Identifier: GPL-3.0-only

//! Общие хелперы билдера (порт Go-утилит cfgbuild). Конфиг строится как
//! `serde_json::Value`: Map без preserve_order = BTreeMap → ключи сортируются
//! по алфавиту, как `json.MarshalIndent` Go (детерминизм golden).

use crate::settings::BuildSettings;
use serde_json::{Map, Value};

/// JSON-объект конфига (сортированные ключи).
pub type Obj = Map<String, Value>;

/// Пустой JSON-объект.
#[must_use]
pub fn obj() -> Obj {
    Map::new()
}

/// «a,b,c» → массив строк (без пустых элементов, trim).
#[must_use]
pub fn split_csv(s: &str) -> Vec<Value> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| Value::String(p.to_string()))
        .collect()
}

/// Адрес является IP-литералом (для dns-direct full: списка).
#[must_use]
pub fn is_ip_addr(s: &str) -> bool {
    s.trim().parse::<std::net::IpAddr>().is_ok()
}

/// Многострочник → строки: пустые/пробельные и #-комментарии пропускаются,
/// значения тримятся (порт SplitLinesSkipSharp).
#[must_use]
pub fn split_lines_skip_sharp(s: &str) -> Vec<Value> {
    s.split(['\n', '\r'])
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| Value::String(line.to_string()))
        .collect()
}

/// []string → []Value.
#[must_use]
pub fn strings_to_value(list: &[String]) -> Vec<Value> {
    list.iter().map(|s| Value::String(s.clone())).collect()
}

/// Допустимые уровни журнала sing-box; неизвестное/пустое → "info".
#[must_use]
pub fn normalize_log_level(level: &str) -> String {
    let l = level.trim().to_lowercase();
    match l.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic" => l,
        _ => "info".into(),
    }
}

/// Платформа сборки/выполнения для tun-name и процессных правил (порт goosOf).
#[must_use]
pub fn goos_of(st: &BuildSettings) -> String {
    if !st.goos.is_empty() {
        return st.goos.clone();
    }
    match std::env::consts::OS {
        "macos" => "darwin".into(),
        other => other.into(),
    }
}

/// Содержит ли список строку (порт containsStr).
#[must_use]
pub fn contains_str(list: &[String], s: &str) -> bool {
    list.iter().any(|v| v == s)
}
