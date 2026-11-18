// SPDX-License-Identifier: GPL-3.0-only

//! `plan_insert` — расчёт вставки нового пользовательского набора (порт Go
//! `api/preset_plan.go`). Чистая функция: ничего не читает из хранилища и не
//! пишет; применяют Create/Import (и будущий перенос из NekoBox пачками).

#![allow(clippy::result_large_err)] // tonic::Status велик по природе контракта
use lavray_presets::limits::MAX_CUSTOM_PRESETS;
use lavray_presets::{Preset, builtin_presets, mint_id, prepare_user};
use tonic::Status;

use crate::preset_view::display_name;

/// Итог `plan_insert`.
pub struct InsertPlan {
    /// Вставляемый набор: копия входного с присвоенным id.
    pub preset: Preset,
    /// Весь список пользовательских наборов после вставки.
    pub list: Vec<Preset>,
}

/// Считает вставку набора `input` в список `existing`.
///
/// Присваивает свободный id `custom:<slug>` по имени (id из входа и id
/// встроенных занять не может), ставит builtin=false, ревизию 1, текущую
/// версию схемы и `$schema`, приводит к хранимому виду и проверяет
/// (`prepare_user`). Источник копии не трогает — его решает вызывающий.
///
/// Ошибки: RESOURCE_EXHAUSTED — уже `MAX_CUSTOM_PRESETS` наборов;
/// INVALID_ARGUMENT — набор не прошёл проверку.
pub fn plan_insert(existing: &[&Preset], input: &Preset) -> Result<InsertPlan, Status> {
    if existing.len() >= MAX_CUSTOM_PRESETS {
        return Err(Status::resource_exhausted(format!(
            "уже {} наборов из {MAX_CUSTOM_PRESETS}",
            existing.len()
        )));
    }
    let reserved = builtin_presets().map_err(|e| Status::internal(format!("builtin: {e}")))?;
    let taken =
        |id: &str| existing.iter().any(|p| p.id == id) || reserved.iter().any(|b| b.id == id);
    let mut p = input.clone();
    p.id = mint_id(&display_name(&p), &taken);
    p.builtin = false;
    p.revision = 1;
    p.version = lavray_presets::SCHEMA_VERSION;
    p.schema = lavray_presets::SCHEMA_REF.into();
    prepare_user(&mut p).map_err(|e| Status::invalid_argument(e.0))?;
    let mut list = Vec::with_capacity(existing.len() + 1);
    list.extend(existing.iter().map(|p| (*p).clone()));
    let preset = p.clone();
    list.push(p);
    Ok(InsertPlan { preset, list })
}
