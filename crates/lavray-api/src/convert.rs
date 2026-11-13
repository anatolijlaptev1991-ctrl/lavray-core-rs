// SPDX-License-Identifier: GPL-3.0-only

//! Конверсии model ↔ proto для API-слоя (волна 6): SettingValue ↔ JSON,
//! дескрипторы настроек. Паритет контракта lavray.v1.

use lavray_model::{SettingDescriptor, SettingType};
use lavray_proto::v1 as pb;

/// model SettingType → proto SettingType.
#[must_use]
pub fn setting_type_to_proto(t: SettingType) -> pb::SettingType {
    match t {
        SettingType::String => pb::SettingType::String,
        SettingType::Bool => pb::SettingType::Bool,
        SettingType::Int => pb::SettingType::Int,
        SettingType::Double => pb::SettingType::Double,
        SettingType::StringList => pb::SettingType::StringList,
        SettingType::Json => pb::SettingType::Json,
    }
}

/// model SettingDescriptor → proto SettingDescriptor.
#[must_use]
pub fn descriptor_to_proto(d: &SettingDescriptor) -> pb::SettingDescriptor {
    pb::SettingDescriptor {
        key: d.key.clone(),
        r#type: setting_type_to_proto(d.r#type) as i32,
        group_id: d.group_id.clone(),
        default_value_json: non_empty(&d.default_value),
        requires_profile_restart: d.requires_profile_restart,
        requires_app_restart: d.requires_app_restart,
        shell_owned: d.shell_owned,
        deprecated_by: non_empty(&d.deprecated_by),
    }
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// JSON-значение настройки → proto SettingValue (oneof).
#[must_use]
pub fn json_to_setting_value(v: &serde_json::Value) -> pb::SettingValue {
    use pb::setting_value::Value as V;
    let value = match v {
        serde_json::Value::String(s) => V::StringValue(s.clone()),
        serde_json::Value::Bool(b) => V::BoolValue(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                V::IntValue(i)
            } else {
                V::DoubleValue(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::Array(arr) => V::StringListValue(pb::StringList {
            items: arr
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
        }),
        // Объект/null — как JSON-строка (тип json).
        other => V::JsonValue(other.to_string()),
    };
    pb::SettingValue { value: Some(value) }
}

/// proto SettingValue → JSON-значение настройки.
#[must_use]
pub fn setting_value_to_json(sv: &pb::SettingValue) -> serde_json::Value {
    use pb::setting_value::Value as V;
    match &sv.value {
        Some(V::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(V::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(V::IntValue(i)) => serde_json::json!(i),
        Some(V::DoubleValue(d)) => serde_json::json!(d),
        Some(V::StringListValue(l)) => serde_json::Value::Array(
            l.items
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        ),
        Some(V::JsonValue(s)) => {
            serde_json::from_str(s).unwrap_or(serde_json::Value::String(s.clone()))
        }
        None => serde_json::Value::Null,
    }
}
