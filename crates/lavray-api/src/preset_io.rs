// SPDX-License-Identifier: GPL-3.0-only

//! Обмен наборами файлом (порт Go `api/preset_exchange.go`, T-80). Экспорт —
//! JSON набора (2 пробела, пустые списки явные); импорт ВСЕГДА создаёт новый
//! пользовательский набор: id, ревизию, builtin и источник из файла ядро не
//! берёт (файл не может занять id встроенного набора).

#![allow(clippy::result_large_err)] // tonic::Status велик по природе контракта
use lavray_presets::{Preset, SCHEMA_VERSION, load_preset, slugify};
use lavray_store::Store;
use std::sync::MutexGuard;
use tonic::Status;

use crate::preset_plan::plan_insert;
use crate::preset_repo::builtin_by_id;
use crate::preset_view::{builtin_revisions, display_name, preset_out, safe_file_stem};
use lavray_proto::v1 as pb;

/// Лимит файла импорта (1 МиБ, Go MaxImportBytes).
pub const MAX_IMPORT_BYTES: usize = 1 << 20;

/// Имя набора, если в файле его нет (Go importedFallbackName).
pub const IMPORTED_FALLBACK_NAME: &str = "Imported preset";

/// Экспорт: JSON набора (встроенного тоже) и имя файла без расширения.
pub fn export_preset(
    st: &MutexGuard<'_, Store>,
    id: &str,
) -> Result<pb::ExportPresetResponse, Status> {
    let Some(p) = find_preset(st, id)? else {
        return Err(Status::not_found(format!("набор {id:?}")));
    };
    let json = export_json(&p)?;
    let name = if p.builtin {
        p.id.clone()
    } else {
        safe_file_stem(&slugify(&display_name(&p)))
    };
    Ok(pb::ExportPresetResponse {
        json,
        suggested_name: name,
    })
}

/// JSON файла набора: MarshalIndent 2 пробела + «\n» (Go ExportJSON). Пустые
/// списки в Rust сериализуются как [] сами (паритет fillEmptyLists).
pub fn export_json(p: &Preset) -> Result<String, Status> {
    serde_json::to_string_pretty(p)
        .map(|mut s| {
            s.push('\n');
            s
        })
        .map_err(|e| Status::internal(format!("экспорт набора {:?}: {e}", p.id)))
}

/// Импорт: файл LAVRay (детект по ключу `routing`; маршрут NekoRay — отдельная
/// работа волны 6.5, пока UNIMPLEMENTED) → новый пользовательский набор.
pub fn import_preset(
    st: &MutexGuard<'_, Store>,
    json: &str,
) -> Result<(pb::RoutingPreset, Vec<String>), Status> {
    if json.len() > MAX_IMPORT_BYTES {
        return Err(Status::resource_exhausted(format!(
            "файл больше {MAX_IMPORT_BYTES} байт"
        )));
    }
    let top: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(json).map_err(|e| {
            Status::invalid_argument(format!("формат файла: ожидался JSON-объект: {e}"))
        })?;
    if top.get("routing").is_none() {
        // Ключи маршрута NekoRay (Go nekoKeys).
        const NEKO_KEYS: [&str; 6] = [
            "domainStrategy",
            "rules",
            "conn",
            "bypass_lan",
            "bypass_chn",
            "bypass_gfw",
        ];
        if NEKO_KEYS.iter().any(|k| top.contains_key(*k)) {
            return Err(Status::unimplemented(
                "конвертер маршрутов NekoRay — волна 6.5; файл LAVRay содержит ключ routing",
            ));
        }
        return Err(Status::invalid_argument(
            "формат файла: нет ни routing, ни полей маршрута NekoRay",
        ));
    }
    // Вставка выставит свою версию схемы — версию файла проверяем здесь.
    let version = top
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if version == 0 || version > u64::from(SCHEMA_VERSION) {
        return Err(Status::invalid_argument(format!(
            "версия схемы {version} не поддерживается (поддерживается ≤ {SCHEMA_VERSION})"
        )));
    }
    let p = load_preset(json).map_err(|e| Status::invalid_argument(e.0))?;
    let out = insert_imported(st, p)?;
    Ok((out, Vec::new()))
}

/// Очистить всё, что файл не вправе задавать, и вставить (PlanInsert выдаёт
/// id и ревизию 1, проверяет набор и лимиты).
pub fn insert_imported(
    st: &MutexGuard<'_, Store>,
    mut p: Preset,
) -> Result<pb::RoutingPreset, Status> {
    p.builtin = false;
    p.source_id.clear();
    p.source_revision = 0;
    if display_name(&p).is_empty() || p.name.is_empty() {
        p.name = crate::preset_view::name_en(IMPORTED_FALLBACK_NAME);
    }
    let builtin =
        lavray_presets::builtin_presets().map_err(|e| Status::internal(format!("builtin: {e}")))?;
    let mut made: Option<Preset> = None;
    crate::preset_repo::modify(st, |_st, list| {
        let plan = plan_insert(list, &p)?;
        made = Some(plan.preset.clone());
        Ok(plan.list)
    })?;
    let p = made.expect("успешный modify всегда заполняет made");
    Ok(preset_out(&p, &builtin_revisions(&builtin)))
}

/// Встроенный или пользовательский набор по id (None — такого нет).
pub fn find_preset(st: &MutexGuard<'_, Store>, id: &str) -> Result<Option<Preset>, Status> {
    if id.is_empty() {
        return Ok(None);
    }
    let builtin =
        lavray_presets::builtin_presets().map_err(|e| Status::internal(format!("builtin: {e}")))?;
    if let Some(p) = builtin_by_id(&builtin, id) {
        return Ok(Some(p.clone()));
    }
    let custom = crate::preset_repo::read(st)?;
    Ok(custom.into_iter().find(|p| p.id == id))
}
