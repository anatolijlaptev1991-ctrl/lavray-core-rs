// SPDX-License-Identifier: GPL-3.0-only

//! Каталог настроек LAVRay (порт Go `model/settings.go` + `settings_update.go`).
//! SettingDescriptor — элемент карты настроек; DescribeSettings (SettingsService)
//! отдаёт этот каталог UI. Значения хранятся в таблице settings как JSON.

use serde::{Deserialize, Serialize};

pub mod descriptors;
pub mod readers;
pub mod update;

/// Тип значения настройки (proto SettingType).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettingType {
    #[default]
    #[serde(rename = "string")]
    String,
    #[serde(rename = "bool")]
    Bool,
    #[serde(rename = "int")]
    Int,
    #[serde(rename = "double")]
    Double,
    #[serde(rename = "string_list")]
    StringList,
    #[serde(rename = "json")]
    Json,
}

/// Элемент карты настроек (паритет Go SettingDescriptor).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingDescriptor {
    pub key: String,
    pub r#type: SettingType,
    pub group_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_value: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub requires_profile_restart: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub requires_app_restart: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shell_owned: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub deprecated_by: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub internal: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub backup_exclude: bool,
}

impl SettingDescriptor {
    /// Конструктор для компактного каталога.
    pub fn new(key: &str, t: SettingType, group: &str) -> Self {
        Self {
            key: key.into(),
            r#type: t,
            group_id: group.into(),
            ..Default::default()
        }
    }
    /// Значение по умолчанию (JSON).
    #[must_use]
    pub fn def(mut self, v: &str) -> Self {
        self.default_value = v.into();
        self
    }
    /// Требует перезапуска профиля.
    #[must_use]
    pub fn restart(mut self) -> Self {
        self.requires_profile_restart = true;
        self
    }
    /// Читает оболочка, ядро хранит.
    #[must_use]
    pub fn shell(mut self) -> Self {
        self.shell_owned = true;
        self
    }
    /// Прежнее имя ключа DataStore NekoBox (миграция §5.4).
    #[must_use]
    pub fn dep(mut self, old: &str) -> Self {
        self.deprecated_by = old.into();
        self
    }
}

/// Служебный ключ с постоянным HWID установки (D-02).
pub const SETTING_HWID_ID: &str = "sub.hwid_id";

/// Секции UI настроек (stable-ключи).
pub const SETTING_GROUPS: &[&str] = &[
    "inbound", "test", "routing", "sub", "remember", "ui", "tun", "hotkeys", "core", "security",
    "mux", "update", "misc", "agent",
];

/// Каталог известных ключей LAVRay (база + служебные обновления).
#[must_use]
pub fn setting_descriptors() -> Vec<SettingDescriptor> {
    let mut out = descriptors::base_descriptors();
    out.extend(update::update_internal_descriptors());
    out
}

/// Ключ настроек не входит в резервную копию (T-83).
#[must_use]
pub fn backup_excluded(key: &str) -> bool {
    setting_descriptors()
        .iter()
        .find(|d| d.key == key)
        .is_some_and(|d| d.backup_exclude)
}
