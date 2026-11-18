// SPDX-License-Identifier: GPL-3.0-only

//! Хранилище пользовательских наборов (порт Go `api/preset_repo.go`): один
//! JSON-массив в `meta['routing.custom_presets']`. Атомарность
//! чтение-изменение-запись даёт общий лок `Arc<Mutex<Store>>` (в Go —
//! отдельный мьютекс репо): вся транзакция проходит под одним локом.
//! Повреждённая запись — DATA_LOSS: молча принять её за «наборов нет»
//! значило бы затереть следующей записью.

#![allow(clippy::result_large_err)] // tonic::Status велик по природе контракта

use lavray_presets::Preset;
use lavray_presets::limits::MAX_ALL_CUSTOM_BYTES;
use lavray_store::Store;
use std::sync::MutexGuard;
use tonic::Status;

/// Ключ meta со списком пользовательских наборов (JSON-массив).
pub const META_CUSTOM_PRESETS: &str = "routing.custom_presets";

/// Атомарно (под уже взятым локом стора): прочитать список, отдать `f`
/// вместе с самим стором (активный набор/DeletePreset пишет в той же
/// транзакции), записать результат. Ошибка `f` (включая ABORTED/NOT_FOUND)
/// ничего не пишет. Результат больше `MAX_ALL_CUSTOM_BYTES` —
/// RESOURCE_EXHAUSTED.
pub fn modify(
    st: &MutexGuard<'_, Store>,
    f: impl FnOnce(&Store, &[&Preset]) -> Result<Vec<Preset>, Status>,
) -> Result<(), Status> {
    let cur = read(st)?;
    let refs: Vec<&Preset> = cur.iter().collect();
    let next = f(st, &refs)?;
    let encoded = encode_presets(&next)?;
    st.set_meta(META_CUSTOM_PRESETS, &encoded)
        .map_err(|e| Status::internal(format!("запись наборов: {e}")))
}

/// Прочитать список (вызывать под локом).
pub fn read(st: &Store) -> Result<Vec<Preset>, Status> {
    let raw = st
        .get_meta(META_CUSTOM_PRESETS)
        .map_err(|e| Status::internal(format!("чтение наборов: {e}")))?;
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<Preset>>(&raw).map_err(|e| {
        Status::data_loss(format!(
            "повреждена запись пользовательских наборов (meta {META_CUSTOM_PRESETS}): {e}"
        ))
    })
}

/// Значение meta для списка наборов; больше `MAX_ALL_CUSTOM_BYTES` —
/// RESOURCE_EXHAUSTED (паритет Go encodePresets).
pub fn encode_presets(list: &[Preset]) -> Result<String, Status> {
    let b = serde_json::to_string(list)
        .map_err(|e| Status::internal(format!("сериализация наборов: {e}")))?;
    if b.len() > MAX_ALL_CUSTOM_BYTES {
        return Err(Status::resource_exhausted(format!(
            "наборы занимают {} байт, предел {MAX_ALL_CUSTOM_BYTES}",
            b.len()
        )));
    }
    Ok(b)
}

/// Позиция набора с id в списке (None — нет).
#[must_use]
pub fn index_of(list: &[&Preset], id: &str) -> Option<usize> {
    list.iter().position(|p| p.id == id)
}

/// Встроенный набор по id из загруженного списка builtin (None — нет).
#[must_use]
pub fn builtin_by_id<'a>(builtin: &'a [Preset], id: &str) -> Option<&'a Preset> {
    builtin.iter().find(|p| p.id == id)
}
