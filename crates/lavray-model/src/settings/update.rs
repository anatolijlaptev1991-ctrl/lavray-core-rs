// SPDX-License-Identifier: GPL-3.0-only

//! Служебные настройки подсистемы обновлений (T-75, порт Go
//! `model/settings_update.go`). Хранят принятый корень доверия и монотонные
//! счётчики защиты от отката метаданных. SetSettings их не принимает,
//! GetSettings не отдаёт, резервная копия исключает.

use super::{SettingDescriptor, SettingType};

/// Служебные ключи подсистемы обновлений (T-75).
pub const SETTING_UPDATE_ROOT_JSON: &str = "update.root_json";
pub const SETTING_UPDATE_ROOT_VERSION: &str = "update.root_version";
pub const SETTING_UPDATE_TIMESTAMP_VERSION: &str = "update.timestamp_version";
pub const SETTING_UPDATE_SERIAL_STABLE: &str = "update.serial_stable";
pub const SETTING_UPDATE_SERIAL_BETA: &str = "update.serial_beta";
pub const SETTING_UPDATE_LAST_CHECKED: &str = "update.last_checked_at";
pub const SETTING_UPDATE_LAST_URL: &str = "update.last_url";

/// Все служебные ключи обновлений (Internal + BackupExclude).
pub const UPDATE_INTERNAL_KEYS: &[&str] = &[
    SETTING_UPDATE_ROOT_JSON,
    SETTING_UPDATE_ROOT_VERSION,
    SETTING_UPDATE_TIMESTAMP_VERSION,
    SETTING_UPDATE_SERIAL_STABLE,
    SETTING_UPDATE_SERIAL_BETA,
    SETTING_UPDATE_LAST_CHECKED,
    SETTING_UPDATE_LAST_URL,
];

/// Служебные дескрипторы обновлений (все Internal + BackupExclude).
pub fn update_internal_descriptors() -> Vec<SettingDescriptor> {
    UPDATE_INTERNAL_KEYS
        .iter()
        .map(|k| {
            let t = if *k == SETTING_UPDATE_ROOT_JSON || *k == SETTING_UPDATE_LAST_URL {
                SettingType::String
            } else {
                SettingType::Int
            };
            SettingDescriptor {
                internal: true,
                backup_exclude: true,
                ..SettingDescriptor::new(k, t, "update")
            }
        })
        .collect()
}
