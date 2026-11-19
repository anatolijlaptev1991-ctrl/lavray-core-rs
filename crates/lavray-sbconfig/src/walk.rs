// SPDX-License-Identifier: GPL-3.0-only

//! Семантические проверки конфига (decode-стадия Go): unknown field по
//! порядку ключей, типы listen_port/server_port, unknown outbound type,
//! enum dns.strategy, duplicate inbound tag, rule-set файлы.

use crate::schema::{
    DNS_STRATEGIES, INBOUND_TYPES, OUTBOUND_TYPES, TOP_FIELDS, U16_FIELDS, inbound_struct,
};
use serde_json::{Map, Value};

/// Прогнать все проверки; Err — текст Go (без префикса «decode config …»).
pub fn walk(root: &Map<String, Value>) -> Result<(), String> {
    // 1) unknown top-level поле — по порядку следования во входе
    //    (serde_json preserve_order).
    for key in root.keys() {
        if !TOP_FIELDS.contains(&key.as_str()) {
            return Err(format!("{key}: json: unknown field \"{key}\""));
        }
    }
    // 2) inbounds
    if let Some(inbounds) = root.get("inbounds").and_then(Value::as_array) {
        for (i, item) in inbounds.iter().enumerate() {
            check_inbound(i, item)?;
        }
        check_dup_tags(inbounds, "inbound")?;
    }
    // 3) outbounds
    if let Some(outbounds) = root.get("outbounds").and_then(Value::as_array) {
        for (i, item) in outbounds.iter().enumerate() {
            check_outbound(i, item)?;
        }
        check_dup_tags(outbounds, "outbound")?;
    }
    // 4) dns.strategy enum
    if let Some(strategy) = root
        .get("dns")
        .and_then(Value::as_object)
        .and_then(|d| d.get("strategy"))
        .and_then(Value::as_str)
        && !DNS_STRATEGIES.contains(&strategy)
    {
        return Err(format!("dns.strategy: unknown domain strategy: {strategy}"));
    }
    // 5) rule-set файлы (initialize router — в бинаре, нужен cwd)
    Ok(())
}

/// rule_set[].path — локальные файлы; Err → «parse rule-set[N]: open …».
#[must_use]
pub fn ruleset_paths(root: &Map<String, Value>) -> Vec<(usize, String)> {
    root.get("route")
        .and_then(Value::as_object)
        .and_then(|r| r.get("rule_set"))
        .and_then(Value::as_array)
        .map_or_default(|sets| {
            sets.iter()
                .enumerate()
                .filter_map(|(i, s)| {
                    let obj = s.as_object()?;
                    let kind = obj.get("type").and_then(Value::as_str)?;
                    (kind == "local").then(|| {
                        let p = obj.get("path").and_then(Value::as_str).unwrap_or_default();
                        (i, p.to_string())
                    })
                })
                .collect()
        })
}

fn check_inbound(i: usize, item: &Value) -> Result<(), String> {
    let obj = item.as_object().ok_or_else(|| {
        format!("inbounds[{i}]: json: cannot unmarshal into Go value of type option.Inbound")
    })?;
    let kind = obj.get("type").and_then(Value::as_str).unwrap_or_default();
    if !INBOUND_TYPES.contains(&kind) {
        // пример recorded: decode config …: outbounds[0]: unknown outbound…
        return Err(format!("inbounds[{i}]: unknown inbound type: {kind}"));
    }
    check_u16_fields(obj, &format!("inbounds[{i}]"), inbound_struct(kind))?;
    Ok(())
}

fn check_outbound(i: usize, item: &Value) -> Result<(), String> {
    let obj = item.as_object().ok_or_else(|| {
        format!("outbounds[{i}]: json: cannot unmarshal into Go value of type option.Outbound")
    })?;
    let kind = obj.get("type").and_then(Value::as_str).unwrap_or_default();
    if !OUTBOUND_TYPES.contains(&kind) {
        return Err(format!("outbounds[{i}]: unknown outbound type: {kind}"));
    }
    Ok(())
}

fn check_u16_fields(
    obj: &Map<String, Value>,
    prefix: &str,
    struct_name: &str,
) -> Result<(), String> {
    for (field, go_field) in U16_FIELDS {
        if let Some(v) = obj.get(*field)
            && !v.is_u64()
            && !v.is_null()
        {
            let got = go_type_name(v);
            let (name, tail) = go_field
                .split_once('.')
                .unwrap_or(("ListenOptions", *field));
            return Err(format!(
                "{prefix}.{field}: json: cannot unmarshal {got} into Go struct field {struct_name}.{name}.{tail} of type uint16"
            ));
        }
    }
    Ok(())
}

fn check_dup_tags(items: &[Value], what: &str) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for item in items {
        if let Some(tag) = item
            .as_object()
            .and_then(|o| o.get("tag"))
            .and_then(Value::as_str)
            && !seen.insert(tag.to_string())
        {
            return Err(format!("duplicate {what} tag: {tag}"));
        }
    }
    Ok(())
}

fn go_type_name(v: &Value) -> &'static str {
    match v {
        Value::String(_) => "string",
        Value::Bool(_) => "bool",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        _ => "number",
    }
}
