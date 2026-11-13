// SPDX-License-Identifier: GPL-3.0-only

//! Лимиты пользовательских наборов (T-80) — паритет с Go `presets/limits.go`.

/// Сколько пользовательских наборов можно хранить.
pub const MAX_CUSTOM_PRESETS: usize = 100;
/// Записей в одном из шести списков.
pub const MAX_LIST_ENTRIES: usize = 10_000;
/// Процессных правил в наборе.
pub const MAX_PROCESS_RULES: usize = 200;
/// Имён процессов в одном правиле.
pub const MAX_PROCESS_NAMES: usize = 64;
/// Длина имени набора в символах.
pub const MAX_NAME_RUNES: usize = 64;
/// Размер всех пользовательских наборов вместе (JSON в meta).
pub const MAX_ALL_CUSTOM_BYTES: usize = 4 << 20;
/// Размер файла при импорте набора.
pub const MAX_IMPORT_BYTES: usize = 1 << 20;
/// Потолок ревизии: один огромный rev не должен навсегда закрыть набор.
pub const MAX_REVISION: u32 = 1_000_000_000;

/// Известные префиксы строк списков (FR-UI-135).
pub const KNOWN_PREFIXES: [&str; 6] = [
    "geosite:", "geoip:", "domain:", "full:", "keyword:", "regexp:",
];

/// Имена платформ процессных правил (SCHEMA §2.1).
pub const KNOWN_PLATFORMS: [&str; 4] = ["windows", "linux", "macos", "openwrt"];

/// Допустимые стратегии домена (пустая = по умолчанию).
pub const DOMAIN_STRATEGIES: [&str; 5] =
    ["", "ipv4_only", "ipv6_only", "prefer_ipv4", "prefer_ipv6"];
