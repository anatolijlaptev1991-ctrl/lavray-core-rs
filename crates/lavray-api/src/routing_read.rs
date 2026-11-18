// SPDX-License-Identifier: GPL-3.0-only

//! Чтение активного набора (вынесено из routing.rs трещоткой размеров):
//! несуществующий id (гонка с удалением, правка данных) работает как
//! встроенный «global» — паритет Go activeOrGlobal.

#![allow(clippy::result_large_err)] // tonic::Status велик по природе контракта

use lavray_presets::Preset;
use lavray_store::Store;
use tonic::Status;

use crate::preset_active::active_preset_id;
use crate::preset_repo;

/// Активный набор; если его id больше не существует — «global».
pub(super) fn active_or_global(st: &Store, builtin: &[Preset]) -> Result<Preset, Status> {
    let cur = active_preset_id(st);
    let custom = preset_repo::read(st)?;
    builtin
        .iter()
        .chain(custom.iter())
        .find(|p| p.id == cur)
        .cloned()
        .or_else(|| builtin.iter().find(|p| p.id == "global").cloned())
        .ok_or_else(|| Status::internal("builtin global не найден"))
}
