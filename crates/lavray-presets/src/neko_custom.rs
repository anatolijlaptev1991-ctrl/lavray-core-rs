// SPDX-License-Identifier: GPL-3.0-only

//! Разбор поля custom RoutingBean (порт Go extractCustomRules):
//! process_name → процессные правила (§2.1: *.exe — windows-only,
//! прочие — linux+macos), остальные правила — custom_rules строкой JSON.

use crate::types::ProcessRule;
use crate::validate::ValidationError;

#[derive(serde::Deserialize)]
struct NekoCustom {
    #[serde(default)]
    rules: Vec<serde_json::Map<String, serde_json::Value>>,
}

/// Разделить custom: process_name → процессные правила (§2.1: *.exe —
/// windows-only, прочие — linux+macos), остальное — custom_rules строкой.
pub(crate) fn extract_custom_rules(
    custom: &str,
) -> Result<(Vec<ProcessRule>, String, Vec<String>), ValidationError> {
    if custom.trim().is_empty() {
        return Ok((Vec::new(), String::new(), Vec::new()));
    }
    let parsed: NekoCustom = serde_json::from_str(custom)
        .map_err(|e| ValidationError(format!("custom: не является корректным JSON: {e}")))?;
    let mut process = Vec::new();
    let mut rest = Vec::new();
    let mut warnings = Vec::new();
    for rule in parsed.rules {
        let names: Vec<String> = match rule.get("process_name") {
            None => Vec::new(),
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(_) => {
                return Err(ValidationError("custom: process_name нечитаем".into()));
            }
        };
        if names.is_empty() {
            rest.push(serde_json::Value::Object(rule));
            continue;
        }
        let outbound = rule.get("outbound").and_then(|v| v.as_str()).unwrap_or("");
        let mapped = match outbound {
            "proxy" | "" => "proxy",
            "bypass" => "direct",
            "block" => "block",
            other => {
                warnings.push(format!(
                    "custom: неизвестный outbound {other:?} — принято proxy"
                ));
                "proxy"
            }
        };
        let mut win = Vec::new();
        let mut posix = Vec::new();
        for n in names {
            if n.to_lowercase().ends_with(".exe") {
                win.push(n);
            } else {
                posix.push(n);
            }
        }
        if !win.is_empty() {
            process.push(ProcessRule {
                platforms: vec!["windows".into()],
                outbound: mapped.into(),
                process_names: win,
            });
        }
        if !posix.is_empty() {
            process.push(ProcessRule {
                platforms: vec!["linux".into(), "macos".into()],
                outbound: mapped.into(),
                process_names: posix,
            });
        }
    }
    let rest_str = if rest.is_empty() {
        String::new()
    } else {
        serde_json::to_string(&serde_json::json!({ "rules": rest }))
            .map_err(|e| ValidationError(format!("custom_rules: {e}")))?
    };
    Ok((process, rest_str, warnings))
}
