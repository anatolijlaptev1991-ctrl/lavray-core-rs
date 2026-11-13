// SPDX-License-Identifier: GPL-3.0-only

//! Разбор custom-правил набора (FR-UI-137, порт Go `presets/customrules.go`).
//! Принимаются JSON-массив правил sing-box и старый объект `{"rules":[…]}`;
//! хранится массив. Тот же разбор использует cfgbuild — чтение/запись не
//! расходятся. Каждое правило обязано быть объектом.

use serde_json::Value;

/// Предел размера custom_rules_json (256 КиБ).
pub const MAX_CUSTOM_RULES_BYTES: usize = 256 << 10;

/// Ошибка разбора custom-правил (путь + причина).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomRulesError(pub String);

impl std::fmt::Display for CustomRulesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CustomRulesError {}

type Result<T> = std::result::Result<T, CustomRulesError>;

fn err(msg: impl Into<String>) -> CustomRulesError {
    CustomRulesError(msg.into())
}

/// Разбить запись на элементы-объекты. Пустые формы дают пустой вектор.
fn split_custom_rules(raw: &str) -> Result<Vec<Value>> {
    let raw = raw.trim();
    if raw.len() > MAX_CUSTOM_RULES_BYTES {
        return Err(err(format!(
            "custom_rules: {} байт, предел {MAX_CUSTOM_RULES_BYTES}",
            raw.len()
        )));
    }
    if raw.is_empty() || raw == "null" {
        return Ok(Vec::new());
    }
    let items: Vec<Value> = match raw.as_bytes()[0] {
        b'[' => serde_json::from_str(raw).map_err(|e| err(format!("custom_rules: {e}")))?,
        b'{' => {
            let obj: Value =
                serde_json::from_str(raw).map_err(|e| err(format!("custom_rules: {e}")))?;
            let map = obj
                .as_object()
                .ok_or_else(|| err("custom_rules: ожидался объект"))?;
            if map.is_empty() {
                return Ok(Vec::new());
            }
            let inner = map.get("rules").ok_or_else(|| {
                err("custom_rules: в объекте нет поля \"rules\" (ожидался массив правил sing-box или {\"rules\":[…]})")
            })?;
            serde_json::from_value(inner.clone())
                .map_err(|e| err(format!("custom_rules: \"rules\" должно быть массивом: {e}")))?
        }
        _ => {
            return Err(err(
                "custom_rules: ожидался массив правил sing-box или {\"rules\":[…]}",
            ));
        }
    };
    for (i, it) in items.iter().enumerate() {
        if !it.is_object() {
            return Err(err(format!(
                "custom_rules[{i}]: правило должно быть объектом"
            )));
        }
    }
    Ok(items)
}

/// Разобрать запись в список правил для сборки конфига (каждое — объект).
/// Пустая запись — пустой вектор (паритет Go `ParseCustomRules`).
pub fn parse_custom_rules(raw: &str) -> Result<Vec<Value>> {
    split_custom_rules(raw)
}

/// Проверить запись и привести к хранимому виду: компактный JSON-массив
/// объектов; пустой набор — "". Ошибка называет путь (паритет Go
/// `NormalizeCustomRules`).
pub fn normalize_custom_rules(raw: &str) -> Result<String> {
    let items = split_custom_rules(raw)?;
    if items.is_empty() {
        return Ok(String::new());
    }
    // Компактный JSON без HTML-экранирования (serde_json не экранирует <, >, &).
    let buf = serde_json::to_string(&items).map_err(|e| err(format!("custom_rules: {e}")))?;
    if buf.len() > MAX_CUSTOM_RULES_BYTES {
        return Err(err(format!(
            "custom_rules: {} байт после нормализации, предел {MAX_CUSTOM_RULES_BYTES}",
            buf.len()
        )));
    }
    Ok(buf)
}
