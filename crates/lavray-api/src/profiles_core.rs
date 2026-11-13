// SPDX-License-Identifier: GPL-3.0-only

//! Тела profile-CRPC ProfileService (порт Go api/profile_service.go): CRUD
//! поверх store. Вынесено из profiles.rs: impl трейта не может быть разбит
//! между файлами, поэтому логика живёт в свободных функциях.

#![allow(clippy::result_large_err)] // tonic::Status велик по природе
use crate::profile_convert::{profile_from_proto, profile_to_proto};

use lavray_proto::v1 as pb;
use lavray_store::Store;
use tonic::Status;

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

/// Список профилей группы (group_id < 0 — все).
pub(crate) fn list_profiles(
    store: &Store,
    r: &pb::ListProfilesRequest,
) -> Result<pb::ListProfilesResponse, Status> {
    let profiles = store
        .list_profiles(r.group_id.unwrap_or(-1))
        .map_err(internal)?;
    let total = i64::try_from(profiles.len()).unwrap_or(i64::MAX);
    let profiles = profiles.iter().map(profile_to_proto).collect();
    Ok(pb::ListProfilesResponse { profiles, total })
}

/// Профиль по id.
pub(crate) fn get_profile(store: &Store, r: pb::GetProfileRequest) -> Result<pb::Profile, Status> {
    let p = store
        .get_profile(r.id)
        .map_err(|_| Status::not_found(format!("профиль {}", r.id)))?;
    Ok(profile_to_proto(&p))
}

/// Создать профиль (id назначает хранилище).
pub(crate) fn create_profile(
    store: &Store,
    r: pb::CreateProfileRequest,
) -> Result<pb::Profile, Status> {
    let p = r
        .profile
        .ok_or_else(|| Status::invalid_argument("profile обязателен"))?;
    let mut m = profile_from_proto(&p);
    m.id = 0;
    let id = store.create_profile(&m).map_err(internal)?;
    let created = store.get_profile(id).map_err(internal)?;
    Ok(profile_to_proto(&created))
}

/// Обновить профиль (полное замещение; нужный перезапуск профиля — всегда true).
pub(crate) fn update_profile(
    store: &Store,
    r: pb::UpdateProfileRequest,
) -> Result<pb::UpdateProfileResponse, Status> {
    let p = r
        .profile
        .ok_or_else(|| Status::invalid_argument("profile обязателен"))?;
    let m = profile_from_proto(&p);
    store.update_profile(&m).map_err(internal)?;
    let updated = store.get_profile(m.id).map_err(internal)?;
    Ok(pb::UpdateProfileResponse {
        profile: Some(profile_to_proto(&updated)),
        needs_profile_restart: true,
    })
}

/// Удалить профили по id.
pub(crate) fn delete_profiles(store: &Store, ids: &[i64]) -> Result<pb::Empty, Status> {
    for id in ids {
        store.delete_profile(*id).map_err(internal)?;
    }
    Ok(pb::Empty {})
}

/// Порядок профилей в группе.
pub(crate) fn reorder_profiles(
    store: &Store,
    r: &pb::ReorderProfilesRequest,
) -> Result<pb::Empty, Status> {
    store
        .reorder_profiles(r.group_id, &r.ordered_ids)
        .map_err(internal)?;
    Ok(pb::Empty {})
}

/// Сброс счётчиков трафика по id.
pub(crate) fn reset_traffic(store: &Store, ids: &[i64]) -> Result<pb::Empty, Status> {
    for id in ids {
        store
            .save_traffic(*id, &lavray_model::TrafficCounters::default())
            .map_err(internal)?;
    }
    Ok(pb::Empty {})
}
