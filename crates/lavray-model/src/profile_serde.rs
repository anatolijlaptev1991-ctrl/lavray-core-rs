// SPDX-License-Identifier: GPL-3.0-only

//! Сериализация Profile: `detail` сливается в顶层 объект по полю `type`
//! (паритет Go `model.Profile.MarshalJSON/UnmarshalJSON`).

use crate::detail::Detail;
use crate::profile::{Profile, ProfileType, TestResult, TrafficCounters};
use crate::stream::StreamSettings;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Промежуточное представление для serde (без detail — он сливается вручную).
#[derive(Serialize, Deserialize)]
struct ProfileRepr {
    #[serde(default)]
    id: i64,
    #[serde(default)]
    group_id: i64,
    r#type: ProfileType,
    #[serde(default)]
    name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    port: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    favorite: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    notes: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    manual: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    geo: String,
    // Go `test_result,omitempty`: omitempty НЕ опускает структуры → всегда {}.
    #[serde(default)]
    test_result: TestResult,
    #[serde(default)]
    traffic: TrafficCounters,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    custom_outbound_json: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    custom_config_json: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    custom_fields_confirmed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stream: Option<StreamSettings>,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    created_at_ms: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    updated_at_ms: i64,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip_serializing_if требует &i64
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

impl Serialize for Profile {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let repr = ProfileRepr {
            id: self.id,
            group_id: self.group_id,
            r#type: self.r#type,
            name: self.name.clone(),
            address: self.address.clone(),
            port: self.port,
            favorite: self.favorite,
            tags: self.tags.clone(),
            notes: self.notes.clone(),
            manual: self.manual,
            geo: self.geo.clone(),
            test_result: self.test_result.clone(),
            traffic: self.traffic.clone(),
            custom_outbound_json: self.custom_outbound_json.clone(),
            custom_config_json: self.custom_config_json.clone(),
            custom_fields_confirmed: self.custom_fields_confirmed,
            stream: self.stream.clone(),
            created_at_ms: self.created_at_ms,
            updated_at_ms: self.updated_at_ms,
        };
        let mut obj = match serde_json::to_value(&repr).map_err(serde::ser::Error::custom)? {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        if let Some(detail) = &self.detail {
            obj.insert("detail".into(), detail.to_value());
        }
        Value::Object(obj).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let Value::Object(mut obj) = Value::deserialize(deserializer)? else {
            return Err(serde::de::Error::custom("profile: ожидался объект"));
        };
        let detail_value = obj.remove("detail");
        let repr: ProfileRepr =
            serde_json::from_value(Value::Object(obj)).map_err(serde::de::Error::custom)?;
        let detail = detail_value
            .filter(|v| !v.is_null())
            .map(|v| detail_from_value(repr.r#type, v))
            .transpose()
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            id: repr.id,
            group_id: repr.group_id,
            r#type: repr.r#type,
            name: repr.name,
            address: repr.address,
            port: repr.port,
            favorite: repr.favorite,
            tags: repr.tags,
            notes: repr.notes,
            manual: repr.manual,
            geo: repr.geo,
            test_result: repr.test_result,
            traffic: repr.traffic,
            custom_outbound_json: repr.custom_outbound_json,
            custom_config_json: repr.custom_config_json,
            custom_fields_confirmed: repr.custom_fields_confirmed,
            stream: repr.stream,
            detail,
            created_at_ms: repr.created_at_ms,
            updated_at_ms: repr.updated_at_ms,
        })
    }
}

/// Разобрать detail по типу профиля (тип задаёт вариант, как в Go).
fn detail_from_value(t: ProfileType, v: Value) -> Result<Detail, String> {
    fn de<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, String> {
        serde_json::from_value(v).map_err(|e| e.to_string())
    }
    Ok(match t {
        ProfileType::Socks | ProfileType::Http => Detail::SocksHttp(de(v)?),
        ProfileType::Shadowsocks => Detail::Shadowsocks(de(v)?),
        ProfileType::VMess => Detail::VMess(de(v)?),
        ProfileType::Trojan | ProfileType::Vless => Detail::TrojanVless(de(v)?),
        ProfileType::Naive => Detail::Naive(de(v)?),
        ProfileType::Hysteria2 => Detail::Hysteria2(de(v)?),
        ProfileType::Tuic => Detail::Tuic(de(v)?),
        ProfileType::CustomOutbound | ProfileType::CustomConfig | ProfileType::CustomExternal => {
            Detail::Custom(de(v)?)
        }
        ProfileType::Chain => Detail::Chain(de(v)?),
    })
}
