// SPDX-License-Identifier: GPL-3.0-only

//! Как набор виден клиенту (порт Go `api/preset_view.go`): имя для показа,
//! признак source_updated, имя копии и безопасное имя файла экспорта.

#![allow(clippy::result_large_err)] // tonic::Status велик по природе контракта
use lavray_presets::limits::MAX_NAME_RUNES;
use lavray_presets::{Localized, Preset};
use std::collections::HashMap;

use crate::preset_convert::preset_to_proto;
use lavray_proto::v1 as pb;

/// Приписка к имени копии, пока клиент не переименовал её.
pub const COPY_SUFFIX: &str = " (copy)";

/// Имя набора для показа: en, затем ru/zh/es/de, затем id.
#[must_use]
pub fn display_name(p: &Preset) -> String {
    if let Some(name) = p.name.get("en").filter(|s| !s.is_empty()) {
        return name.to_string();
    }
    for lang in ["ru", "zh", "es", "de"] {
        if let Some(name) = p.name.get(lang).filter(|s| !s.is_empty()) {
            return name.to_string();
        }
    }
    p.id.clone()
}

/// Имя копии «<имя> (copy)», укладывающееся в предел имени.
#[must_use]
pub fn copy_name(name: &str) -> String {
    let keep = MAX_NAME_RUNES - COPY_SUFFIX.chars().count();
    let mut head: String = name.chars().take(keep).collect();
    head.push_str(COPY_SUFFIX);
    head
}

/// Набор → proto с вычисленным source_updated: ревизия встроенного источника
/// выше той, с которой снята копия.
#[must_use]
pub fn preset_out(p: &Preset, builtin_revisions: &HashMap<String, u32>) -> pb::RoutingPreset {
    let mut r = preset_to_proto(p, &display_name(p));
    if !p.source_id.is_empty()
        && let Some(cur) = builtin_revisions.get(&p.source_id)
    {
        r.source_updated = *cur > p.source_revision;
    }
    r
}

/// Действующие ревизии builtin-наборов по id.
#[must_use]
pub fn builtin_revisions(builtin: &[Preset]) -> HashMap<String, u32> {
    builtin.iter().map(|p| (p.id.clone(), p.revision)).collect()
}

/// Имя файла экспорта без расширения: зарезервированные имена устройств
/// Windows (con, nul, com1…) получают приставку, иначе «Сохранить как» их
/// отвергнет (порт Go safeFileStem).
#[must_use]
pub fn safe_file_stem(stem: &str) -> String {
    let bytes = stem.as_bytes();
    let reserved = matches!(stem, "con" | "prn" | "aux" | "nul")
        || (bytes.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && bytes[3].is_ascii_digit()
            && bytes[3] != b'0');
    if reserved {
        format!("preset-{stem}")
    } else {
        stem.to_string()
    }
}

/// Локализованное имя из одного en-значения (для create-from-values).
#[must_use]
pub fn name_en(text: &str) -> Localized {
    let mut n = Localized::new();
    n.insert("en", text);
    n
}
