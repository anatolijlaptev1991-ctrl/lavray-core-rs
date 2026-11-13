// SPDX-License-Identifier: GPL-3.0-only

//! Тела group-RPC ProfileService (порт Go api/profile_service.go): CRUD групп
//! поверх store. Вынесено из profiles.rs ради трещотки размеров.

#![allow(clippy::result_large_err)] // tonic::Status велик по природе
use crate::group_convert::{group_from_proto, group_to_proto};

use lavray_proto::v1 as pb;
use lavray_store::Store;
use tonic::Status;

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

/// Список групп в порядке вкладок.
pub(crate) fn list_groups(store: &Store) -> Result<pb::ListGroupsResponse, Status> {
    let groups = store.list_groups().map_err(internal)?;
    Ok(pb::ListGroupsResponse {
        groups: groups.iter().map(group_to_proto).collect(),
    })
}

/// Создать группу (id/tab_order назначает хранилище).
pub(crate) fn create_group(store: &Store, r: pb::CreateGroupRequest) -> Result<pb::Group, Status> {
    let g = r
        .group
        .ok_or_else(|| Status::invalid_argument("group обязателен"))?;
    let mut m = group_from_proto(&g);
    m.id = 0;
    let id = store.create_group(&m).map_err(internal)?;
    let created = store.get_group(id).map_err(internal)?;
    Ok(group_to_proto(&created))
}

/// Обновить группу (kind не меняется, FR-UI-109).
pub(crate) fn update_group(store: &Store, r: pb::UpdateGroupRequest) -> Result<pb::Group, Status> {
    let g = r
        .group
        .ok_or_else(|| Status::invalid_argument("group обязателен"))?;
    let m = group_from_proto(&g);
    store.update_group(&m).map_err(internal)?;
    let updated = store.get_group(m.id).map_err(internal)?;
    Ok(group_to_proto(&updated))
}

/// Удалить группу (гард последней группы FR-UI-107).
pub(crate) fn delete_group(store: &Store, id: i64) -> Result<pb::Empty, Status> {
    store.delete_group(id).map_err(internal)?;
    Ok(pb::Empty {})
}

/// Порядок вкладок групп.
pub(crate) fn reorder_groups(store: &Store, ids: &[i64]) -> Result<pb::Empty, Status> {
    store.reorder_groups(ids).map_err(internal)?;
    Ok(pb::Empty {})
}
