// SPDX-License-Identifier: GPL-3.0-only

//! `rule-set format`: pretty-JSON с нормализацией Go badoption.Listable —
//! массив из одного элемента маршалится СКАЛЯРОМ (recorded rs-format-source),
//! порядок ключей — входной (serde_json preserve_order).

use crate::source::RuleSetParseError;

/// Отформатировать source rule-set (2-space pretty). Ошибки — как parse.
///
/// # Errors
/// Ошибки разбора source JSON.
pub fn format_source(raw: &str) -> Result<String, RuleSetParseError> {
    // Валидация схемой rule-set (та же, что в match).
    crate::parse_source(raw)?;
    let mut value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| RuleSetParseError::Other(e.to_string()))?;
    normalize(&mut value);
    serde_json::to_string_pretty(&value).map_err(|e| RuleSetParseError::Other(e.to_string()))
}

/// Поля-объекты правил: списки длиной 1 → скаляр (MarshalJSON Listable),
/// кроме структурных (type/mode/invert/rules).
fn normalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if k == "type" || k == "mode" || k == "invert" || k == "rules" {
                    normalize(v);
                    continue;
                }
                if let serde_json::Value::Array(arr) = v {
                    if arr.len() == 1 {
                        let mut sole = arr.remove(0);
                        normalize(&mut sole);
                        *v = sole;
                    } else {
                        for item in arr.iter_mut() {
                            normalize(item);
                        }
                    }
                } else {
                    normalize(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                normalize(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_lists_become_scalars() {
        let out = format_source(
            r#"{"version":3,"rules":[{"domain":["a.com","b.com"]},{"domain_keyword":["gemini"]}]}"#,
        )
        .expect("fmt");
        assert!(out.contains(r#""domain": ["#));
        assert!(out.contains(r#""domain_keyword": "gemini""#));
    }

    #[test]
    fn keeps_key_order() {
        // входной порядок полей (не алфавитный): domain_regex до domain
        let out =
            format_source(r#"{"version":3,"rules":[{"domain_regex":["^a$"],"domain":["x.com"]}]}"#)
                .expect("fmt");
        let regex_pos = out.find("domain_regex").expect("regex");
        let domain_pos = out.find("\"domain\"").expect("domain");
        assert!(regex_pos < domain_pos, "порядок входа: {out}");
    }
}
