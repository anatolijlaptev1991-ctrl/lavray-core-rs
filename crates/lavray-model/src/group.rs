// SPDX-License-Identifier: GPL-3.0-only

//! Группа профилей (порт db/Group.hpp, FR-UI-102–113) + per-sub настройки
//! (FR-UI-263) — паритет с Go `model.Group/SubscriptionInfo`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Вид группы (proto Group.Kind); смена после создания запрещена (FR-UI-109).
/// В JSON — число 1/2 (паритет Go `model.GroupKind int`, P2-12 аудита):
/// канонический JSON группы совместим с Go для backup/API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GroupKind {
    /// Обычная группа (proto = 1).
    #[default]
    Basic,
    /// Группа-подписка (proto = 2).
    Subscription,
}

impl Serialize for GroupKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(match self {
            Self::Basic => 1,
            Self::Subscription => 2,
        })
    }
}

impl<'de> Deserialize<'de> for GroupKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = i64::deserialize(deserializer)?;
        Ok(if v == 2 {
            Self::Subscription
        } else {
            Self::Basic
        })
    }
}

/// Информация подписки (FR-UI-127).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_interval_hours: Option<i32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub web_page_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub support_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub announce: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub routing: String,
}

/// Группа профилей + per-sub настройки.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: GroupKind,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subscription_url: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub archive: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub skip_auto_update: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub front_proxy_id: Option<i64>,
    /// Вычисляемое поле: порядок хранится в profiles.sort_key, при записи игнорируется.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_order: Vec<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_info: Option<SubscriptionInfo>,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub last_update_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_interval_min: Option<i32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_agent: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub http_headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub http_basic_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_working_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ui_state: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub tab_order: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub updated_at_ms: i64,
}

impl Default for Group {
    fn default() -> Self {
        Self {
            id: 0,
            name: String::new(),
            kind: GroupKind::Basic,
            subscription_url: String::new(),
            archive: false,
            skip_auto_update: false,
            front_proxy_id: None,
            profile_order: Vec::new(),
            subscription_info: None,
            last_update_ms: 0,
            update_interval_min: None,
            user_agent: String::new(),
            http_headers: BTreeMap::new(),
            http_basic_user: String::new(),
            last_working_url: String::new(),
            ui_state: String::new(),
            tab_order: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip_serializing_if требует &i64
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
