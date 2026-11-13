// SPDX-License-Identifier: GPL-3.0-only

//! Встроенные пресеты (include_str!). Синхронизированы с
//! `lavray/presets/*.json` (паритет с Go `presets.BuiltinPresets`).

use crate::types::Preset;
use crate::validate::ValidationError;

/// Имена 6 builtin-наборов (PRESET-LAV-RU §3a; «Выборочный» — пустой
/// пользовательский набор, не файл). `lav-openwrt` — персональный пресет
/// роутера: адаптация lav-ru без процессных правил (на роутере process_name
/// неприменим — трафик от LAN-устройств; SCHEMA §2.1).
pub const BUILTIN_FILES: [&str; 6] = [
    "lav-ru.json",
    "lav-cn.json",
    "lav-openwrt.json",
    "global.json",
    "all-proxy.json",
    "all-direct.json",
];

const LAV_RU: &str = include_str!("builtin/lav-ru.json");
const LAV_CN: &str = include_str!("builtin/lav-cn.json");
const LAV_OPENWRT: &str = include_str!("builtin/lav-openwrt.json");
const GLOBAL: &str = include_str!("builtin/global.json");
const ALL_PROXY: &str = include_str!("builtin/all-proxy.json");
const ALL_DIRECT: &str = include_str!("builtin/all-direct.json");

/// Содержимое builtin-набора по имени файла.
#[must_use]
pub fn builtin_source(name: &str) -> Option<&'static str> {
    match name {
        "lav-ru.json" => Some(LAV_RU),
        "lav-cn.json" => Some(LAV_CN),
        "lav-openwrt.json" => Some(LAV_OPENWRT),
        "global.json" => Some(GLOBAL),
        "all-proxy.json" => Some(ALL_PROXY),
        "all-direct.json" => Some(ALL_DIRECT),
        _ => None,
    }
}

/// Загрузить все встроенные пресеты (разобрать + провалидировать).
pub fn builtin_presets() -> Result<Vec<Preset>, ValidationError> {
    let mut out = Vec::with_capacity(BUILTIN_FILES.len());
    for name in BUILTIN_FILES {
        let data =
            builtin_source(name).ok_or_else(|| ValidationError(format!("builtin: {name}")))?;
        let preset = crate::load_preset(data)?;
        if !preset.builtin {
            return Err(ValidationError(format!("builtin {name}: builtin=false")));
        }
        out.push(preset);
    }
    Ok(out)
}
