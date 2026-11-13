// SPDX-License-Identifier: GPL-3.0-only

//! Профиль — каркас (AbstractBean + ProxyEntity nekoray) + типоспецифичный
//! `Detail`. Канонический JSON: `detail` сливается в顶层 объект по полю `type`
//! (паритет Go `model.Profile.MarshalJSON`).

use crate::detail::Detail;
use crate::stream::StreamSettings;
use serde::{Deserialize, Serialize};

/// Тип профиля (proto enum ProfileType); в БД/JSON — строкой.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileType {
    #[default]
    Socks,
    Http,
    Shadowsocks,
    Trojan,
    #[serde(rename = "vmess")]
    VMess,
    #[serde(rename = "vless")]
    Vless,
    Naive,
    Hysteria2,
    Tuic,
    CustomOutbound,
    CustomConfig,
    CustomExternal,
    Chain,
}

/// Результат тестов: latency_ms None=не тестировали, <0=unavailable, >0=мс.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<i32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub full_report: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tested_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_error: String,
}

/// Накопленный трафик профиля (FR-UI-211).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficCounters {
    #[serde(default)]
    pub uplink_bytes: i64,
    #[serde(default)]
    pub downlink_bytes: i64,
}

/// Общий каркас профиля + типоспецифичная часть Detail (ровно одна).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub id: i64,
    pub group_id: i64,
    pub r#type: ProfileType,
    pub name: String,
    pub address: String,
    pub port: i64,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub notes: String,
    pub manual: bool,
    pub geo: String,
    pub test_result: TestResult,
    pub traffic: TrafficCounters,
    pub custom_outbound_json: String,
    pub custom_config_json: String,
    pub custom_fields_confirmed: bool,
    pub stream: Option<StreamSettings>,
    pub detail: Option<Detail>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: 0,
            group_id: 0,
            r#type: ProfileType::Socks,
            name: String::new(),
            address: String::new(),
            port: 0,
            favorite: false,
            tags: Vec::new(),
            notes: String::new(),
            manual: false,
            geo: String::new(),
            test_result: TestResult::default(),
            traffic: TrafficCounters::default(),
            custom_outbound_json: String::new(),
            custom_config_json: String::new(),
            custom_fields_confirmed: false,
            stream: None,
            detail: None,
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }
}
