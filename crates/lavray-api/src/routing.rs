// SPDX-License-Identifier: GPL-3.0-only

//! RoutingService (волна 6, порт Go `api/routing_service.go`): список наборов
//! (встроенные + пользовательские), чтение, активация; CRUD пользовательских
//! — `preset_edit`, обмен файлом — `preset_io`. Все операции проходят под
//! одним локом `Arc<Mutex<Store>>` — атомарность как у мьютекса репо Go.

use lavray_presets::builtin_presets;
use lavray_proto::v1 as pb;
use lavray_proto::v1::routing_service_server::RoutingService;
use lavray_store::Store;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

use crate::preset_active::{active_preset_id, set_active_preset};
use crate::preset_edit;
use crate::preset_io;
use crate::preset_repo;
use crate::preset_view::{builtin_revisions, display_name, preset_out};
use crate::routing_read::active_or_global;

/// Реализация RoutingService поверх общего хранилища.
pub struct RoutingServiceImpl {
    store: Arc<Mutex<Store>>,
}

impl RoutingServiceImpl {
    /// Создать сервис с общим хранилищем.
    #[must_use]
    pub fn new(store: Arc<Mutex<Store>>) -> Self {
        Self { store }
    }
}

#[allow(clippy::result_large_err)] // tonic::Status велик по природе контракта
fn lock(store: &Arc<Mutex<Store>>) -> Result<std::sync::MutexGuard<'_, Store>, Status> {
    store
        .lock()
        .map_err(|_| Status::internal("хранилище заблокировано"))
}

#[tonic::async_trait]
impl RoutingService for RoutingServiceImpl {
    async fn list_presets(
        &self,
        _request: Request<pb::ListPresetsRequest>,
    ) -> Result<Response<pb::ListPresetsResponse>, Status> {
        let st = lock(&self.store)?;
        let builtin = builtin_presets().map_err(|e| Status::internal(format!("builtin: {e}")))?;
        let custom = preset_repo::read(&st)?;
        let rev = builtin_revisions(&builtin);
        let cur = active_preset_id(&st);
        let mut active = "global".to_string(); // id, которого нет в списке, читается как global
        let mut presets = Vec::with_capacity(builtin.len() + custom.len());
        for p in builtin.iter().chain(custom.iter()) {
            presets.push(preset_out(p, &rev));
            if p.id == cur {
                active.clone_from(&p.id);
            }
        }
        Ok(Response::new(pb::ListPresetsResponse {
            presets,
            active_preset_id: active,
        }))
    }

    async fn get_preset(
        &self,
        request: Request<pb::GetPresetRequest>,
    ) -> Result<Response<pb::RoutingPreset>, Status> {
        let st = lock(&self.store)?;
        let builtin = builtin_presets().map_err(|e| Status::internal(format!("builtin: {e}")))?;
        let Some(p) = preset_io::find_preset(&st, &request.into_inner().id)? else {
            return Err(Status::not_found("пресет не найден"));
        };
        let rev = builtin_revisions(&builtin);
        Ok(Response::new(preset_out(&p, &rev)))
    }

    async fn create_preset(
        &self,
        request: Request<pb::CreatePresetRequest>,
    ) -> Result<Response<pb::RoutingPreset>, Status> {
        let st = lock(&self.store)?;
        let m = request.into_inner();
        let out =
            preset_edit::create_preset(&st, m.builtin_source_id.as_deref(), m.preset.as_ref())?;
        Ok(Response::new(out))
    }

    async fn update_preset(
        &self,
        request: Request<pb::UpdatePresetRequest>,
    ) -> Result<Response<pb::UpdatePresetResponse>, Status> {
        let st = lock(&self.store)?;
        let m = request.into_inner();
        let Some(preset) = m.preset else {
            return Err(Status::invalid_argument("preset обязателен"));
        };
        let (out, new_revision) = preset_edit::update_preset(&st, &preset, m.expected_revision)?;
        Ok(Response::new(pb::UpdatePresetResponse {
            needs_profile_restart: false, // движок — волна 7; idle-сервер всегда false
            preset: Some(out),
            new_revision,
        }))
    }

    async fn delete_preset(
        &self,
        request: Request<pb::DeletePresetRequest>,
    ) -> Result<Response<pb::DeletePresetResponse>, Status> {
        let st = lock(&self.store)?;
        Ok(Response::new(preset_edit::delete_preset(
            &st,
            &request.into_inner().id,
        )?))
    }

    async fn activate_preset(
        &self,
        request: Request<pb::ActivatePresetRequest>,
    ) -> Result<Response<pb::ActivatePresetResponse>, Status> {
        // Проверка набора и запись активного id — под тем же локом: иначе
        // DeletePreset между ними оставил бы активным уже удалённый набор.
        let st = lock(&self.store)?;
        let id = request.into_inner().id;
        let Some(p) = preset_io::find_preset(&st, &id)? else {
            return Err(Status::not_found(format!("набор {id:?}")));
        };
        p.validate().map_err(|e| Status::invalid_argument(e.0))?;
        set_active_preset(&st, &p.id)?;
        Ok(Response::new(pb::ActivatePresetResponse {
            needs_profile_restart: false, // движок — волна 7; idle-сервер всегда false
            preview: display_name(&p),
        }))
    }

    async fn get_active_preset(
        &self,
        _request: Request<pb::GetActivePresetRequest>,
    ) -> Result<Response<pb::RoutingPreset>, Status> {
        let st = lock(&self.store)?;
        let builtin = builtin_presets().map_err(|e| Status::internal(format!("builtin: {e}")))?;
        let p = active_or_global(&st, &builtin)?;
        Ok(Response::new(preset_out(&p, &builtin_revisions(&builtin))))
    }

    async fn reset_builtin_preset(
        &self,
        request: Request<pb::ResetBuiltinPresetRequest>,
    ) -> Result<Response<pb::RoutingPreset>, Status> {
        let st = lock(&self.store)?;
        Ok(Response::new(preset_edit::reset_builtin_preset(
            &st,
            &request.into_inner().id,
        )?))
    }

    async fn import_neko_ray_route(
        &self,
        _request: Request<pb::ImportNekoRayRouteRequest>,
    ) -> Result<Response<pb::ImportNekoRayRouteResponse>, Status> {
        // Волна 6.5: конвертер маршрутов NekoRay 4.x (PRESET-LAV-RU §3).
        Err(Status::unimplemented(
            "конвертер маршрутов NekoRay — волна 6.5",
        ))
    }

    async fn export_preset(
        &self,
        request: Request<pb::ExportPresetRequest>,
    ) -> Result<Response<pb::ExportPresetResponse>, Status> {
        let st = lock(&self.store)?;
        Ok(Response::new(preset_io::export_preset(
            &st,
            &request.into_inner().id,
        )?))
    }

    async fn import_preset(
        &self,
        request: Request<pb::ImportPresetRequest>,
    ) -> Result<Response<pb::ImportPresetResponse>, Status> {
        let st = lock(&self.store)?;
        let (preset, warnings) = preset_io::import_preset(&st, &request.into_inner().json)?;
        Ok(Response::new(pb::ImportPresetResponse {
            preset: Some(preset),
            warnings,
        }))
    }
}
