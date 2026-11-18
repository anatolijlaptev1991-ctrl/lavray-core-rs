// SPDX-License-Identifier: GPL-3.0-only

//! Создание/правка/удаление/сброс пользовательских наборов (порт Go
//! `api/preset_service.go` + `api/preset_update.go`, T-80). Встроенные —
//! только чтение: правка через копию, Reset возвращает копию к источнику.
//! Конфликт ревизий — ABORTED; встроенный — FAILED_PRECONDITION.

#![allow(clippy::result_large_err)] // tonic::Status велик по природе контракта
use lavray_presets::{Preset, builtin_presets, new_custom_from, prepare_user};
use lavray_store::Store;
use std::sync::MutexGuard;
use tonic::Status;

use crate::preset_active::{active_preset_id, drop_dns_choice, set_active_preset};
use crate::preset_convert::preset_from_proto;
use crate::preset_plan::plan_insert;
use crate::preset_repo::{builtin_by_id, index_of};
use crate::preset_view::{builtin_revisions, copy_name, display_name, preset_out};
use lavray_proto::v1 as pb;

/// Ровно один из двух источников CreatePreset (иначе INVALID_ARGUMENT).
pub fn create_preset(
    st: &MutexGuard<'_, Store>,
    builtin_source_id: Option<&str>,
    preset: Option<&pb::RoutingPreset>,
) -> Result<pb::RoutingPreset, Status> {
    let src = builtin_source_id.unwrap_or_default().trim();
    if src.is_empty() != preset.is_some() {
        return Err(Status::invalid_argument(
            "укажите ровно одно: builtin_source_id (копия набора) или preset (значения)",
        ));
    }
    let builtin = builtin_presets().map_err(|e| Status::internal(format!("builtin: {e}")))?;
    let mut made: Option<Preset> = None;
    let res = crate::preset_repo::modify(st, |_st, list| {
        let input = if let Some(src) = (!src.is_empty()).then_some(src) {
            // Копия: источник — builtin или свой; имя «<имя> (copy)».
            let base = builtin_by_id(&builtin, src)
                .or_else(|| list.iter().find(|p| p.id == src).copied())
                .ok_or_else(|| Status::not_found(format!("набор {src:?}")))?;
            let mut in_ = new_custom_from(base, "");
            in_.name = crate::preset_view::name_en(&copy_name(&display_name(base)));
            in_
        } else {
            preset_from_proto(preset.expect("ровно одно из двух проверено выше"))
        };
        let plan = plan_insert(list, &input)?;
        made = Some(plan.preset.clone());
        Ok(plan.list)
    });
    res.map(|()| {
        let p = made.expect("успешный modify всегда заполняет made");
        let rev = builtin_revisions(&builtin);
        preset_out(&p, &rev)
    })
}

/// Правка пользовательского набора: устаревшая ревизия — ABORTED.
/// Идентичность, источник и builtin — из хранилища; из запроса — значения.
pub fn update_preset(
    st: &MutexGuard<'_, Store>,
    req: &pb::RoutingPreset,
    expected_revision: i32,
) -> Result<(pb::RoutingPreset, i32), Status> {
    let id = req.id.clone();
    let builtin = builtin_presets().map_err(|e| Status::internal(format!("builtin: {e}")))?;
    let mut saved: Option<Preset> = None;
    let res = crate::preset_repo::modify(st, |_st, list| {
        let i = editable_index(&builtin, list, &id)?;
        let stored = list[i];
        if stored.revision.cast_signed() != expected_revision {
            return Err(Status::aborted(format!(
                "набор {id:?} изменён: ревизия {}, ожидалась {expected_revision} — перечитайте набор",
                stored.revision
            )));
        }
        let next = merge_update(stored, req)?;
        saved = Some(next.clone());
        let mut new_list: Vec<Preset> = list.iter().map(|p| (*p).clone()).collect();
        new_list[i] = next;
        Ok(new_list)
    });
    res.map(|()| {
        let p = saved.expect("успешный modify всегда заполняет saved");
        let out = preset_out(&p, &builtin_revisions(&builtin));
        let rev = out.revision;
        (out, rev)
    })
}

/// Наложение значений запроса на сохранённый набор (Go mergeUpdate): имя не
/// из запроса, а прежнее (все переводы), если клиент его не менял; DNS не
/// присланный остаётся прежним; описание и заметки — из хранилища.
fn merge_update(stored: &Preset, r: &pb::RoutingPreset) -> Result<Preset, Status> {
    let mut next = preset_from_proto(r);
    next.builtin = false;
    next.source_id.clone_from(&stored.source_id);
    next.source_revision = stored.source_revision;
    next.description.clone_from(&stored.description);
    next.maintainer_notes.clone_from(&stored.maintainer_notes);
    if r.display_name == display_name(stored) {
        next.name = stored.name.clone();
    }
    if r.dns.is_none() {
        next.dns = stored.dns.clone();
    }
    prepare_user(&mut next).map_err(|e| Status::invalid_argument(e.0))?;
    next.revision = stored.revision + 1;
    Ok(next)
}

/// Удаление пользовательского набора: активный — переключить на «global»
/// ДО удаления (при сбое набор остаётся, активный всегда существует);
/// затем снять DNS-переопределение удалённого.
pub fn delete_preset(
    st: &MutexGuard<'_, Store>,
    id: &str,
) -> Result<pb::DeletePresetResponse, Status> {
    let builtin = builtin_presets().map_err(|e| Status::internal(format!("builtin: {e}")))?;
    let mut resp = pb::DeletePresetResponse::default();
    let res = crate::preset_repo::modify(st, |st, list| {
        let i = editable_index(&builtin, list, id)?;
        if active_preset_id(st) == id {
            set_active_preset(st, "global")?;
            resp.new_active_id = "global".into();
        }
        let mut new_list: Vec<Preset> = list
            .iter()
            .enumerate()
            .filter(|&(j, _p)| j != i)
            .map(|(_j, p)| (*p).clone())
            .collect();
        new_list.shrink_to_fit();
        Ok(new_list)
    });
    res?;
    drop_dns_choice(st, id)?;
    Ok(resp)
}

/// Возврат копии к исходному встроенному набору: списки, процессные правила,
/// custom-правила и DNS — от источника; имя остаётся; ревизия растёт.
pub fn reset_builtin_preset(
    st: &MutexGuard<'_, Store>,
    id: &str,
) -> Result<pb::RoutingPreset, Status> {
    let builtin = builtin_presets().map_err(|e| Status::internal(format!("builtin: {e}")))?;
    let mut reset: Option<Preset> = None;
    let res = crate::preset_repo::modify(st, |_st, list| {
        let i = editable_index(&builtin, list, id)?;
        let stored = list[i];
        let Some(src) = builtin_by_id(&builtin, &stored.source_id) else {
            return Err(Status::failed_precondition(format!(
                "у набора {id:?} нет встроенного источника, сбрасывать нечего"
            )));
        };
        let fresh = new_custom_from(src, id);
        let mut next = stored.clone();
        next.routing = fresh.routing;
        next.dns = fresh.dns;
        next.source_id.clone_from(&src.id);
        next.source_revision = src.revision;
        prepare_user(&mut next).map_err(|e| Status::invalid_argument(e.0))?;
        next.revision = stored.revision + 1;
        reset = Some(next.clone());
        let mut new_list: Vec<Preset> = list.iter().map(|p| (*p).clone()).collect();
        new_list[i] = next;
        Ok(new_list)
    });
    res.map(|()| {
        let p = reset.expect("успешный modify всегда заполняет reset");
        preset_out(&p, &builtin_revisions(&builtin))
    })
}

/// Позиция пользовательского набора: встроенный — FAILED_PRECONDITION
/// (только чтение), неизвестный — NOT_FOUND (Go editableIndex).
pub fn editable_index(builtin: &[Preset], list: &[&Preset], id: &str) -> Result<usize, Status> {
    if builtin_by_id(builtin, id).is_some() {
        return Err(Status::failed_precondition(format!(
            "встроенный набор {id:?} только для чтения: сделайте копию"
        )));
    }
    index_of(list, id).ok_or_else(|| Status::not_found(format!("набор {id:?}")))
}
