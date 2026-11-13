// SPDX-License-Identifier: GPL-3.0-only

//! ProfileService (волна 6, порт Go api/profile_service.go): делегирующий impl.
//! Тела RPC — в profiles_core.rs / groups_rpc.rs / profiles_io.rs (impl трейта
//! не может быть разбит между файлами; rustfmt::skip держит файл ≤200 строк).
//! Сложные RPC (dedup/custom-fields/тесты) — задел unimplemented.

use crate::groups_rpc as grp;
use crate::profiles_core as core;
use crate::profiles_io::{export_links as io_export_links, import_content as io_import_content};
use lavray_proto::v1 as pb;
use lavray_proto::v1::profile_service_server::ProfileService;
use lavray_store::Store;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

/// Реализация ProfileService поверх хранилища.
pub struct ProfileServiceImpl {
    store: Arc<Mutex<Store>>,
}

impl ProfileServiceImpl {
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

fn unimpl(name: &'static str) -> Status {
    Status::unimplemented(name)
}

#[tonic::async_trait]
#[rustfmt::skip]
impl ProfileService for ProfileServiceImpl {
    async fn list_profiles(&self, request: Request<pb::ListProfilesRequest>) -> Result<Response<pb::ListProfilesResponse>, Status> {
        let r = request.into_inner();
        let store = lock(&self.store)?;
        Ok(Response::new(core::list_profiles(&store, &r)?))
    }
    async fn get_profile(&self, request: Request<pb::GetProfileRequest>) -> Result<Response<pb::Profile>, Status> {
        let r = request.into_inner();
        let store = lock(&self.store)?;
        Ok(Response::new(core::get_profile(&store, r)?))
    }
    async fn create_profile(&self, request: Request<pb::CreateProfileRequest>) -> Result<Response<pb::Profile>, Status> {
        let r = request.into_inner();
        let store = lock(&self.store)?;
        Ok(Response::new(core::create_profile(&store, r)?))
    }
    async fn update_profile(&self, request: Request<pb::UpdateProfileRequest>) -> Result<Response<pb::UpdateProfileResponse>, Status> {
        let r = request.into_inner();
        let store = lock(&self.store)?;
        Ok(Response::new(core::update_profile(&store, r)?))
    }
    async fn delete_profile(&self, request: Request<pb::DeleteProfileRequest>) -> Result<Response<pb::Empty>, Status> {
        let ids = request.into_inner().ids;
        let store = lock(&self.store)?;
        Ok(Response::new(core::delete_profiles(&store, &ids)?))
    }
    async fn reorder_profiles(&self, request: Request<pb::ReorderProfilesRequest>) -> Result<Response<pb::Empty>, Status> {
        let r = request.into_inner();
        let store = lock(&self.store)?;
        Ok(Response::new(core::reorder_profiles(&store, &r)?))
    }
    async fn reset_traffic(&self, request: Request<pb::ResetTrafficRequest>) -> Result<Response<pb::Empty>, Status> {
        let ids = request.into_inner().ids;
        let store = lock(&self.store)?;
        Ok(Response::new(core::reset_traffic(&store, &ids)?))
    }
    async fn list_groups(&self, _: Request<pb::ListGroupsRequest>) -> Result<Response<pb::ListGroupsResponse>, Status> {
        let store = lock(&self.store)?;
        Ok(Response::new(grp::list_groups(&store)?))
    }
    async fn create_group(&self, request: Request<pb::CreateGroupRequest>) -> Result<Response<pb::Group>, Status> {
        let r = request.into_inner();
        let store = lock(&self.store)?;
        Ok(Response::new(grp::create_group(&store, r)?))
    }
    async fn update_group(&self, request: Request<pb::UpdateGroupRequest>) -> Result<Response<pb::Group>, Status> {
        let r = request.into_inner();
        let store = lock(&self.store)?;
        Ok(Response::new(grp::update_group(&store, r)?))
    }
    async fn delete_group(&self, request: Request<pb::DeleteGroupRequest>) -> Result<Response<pb::Empty>, Status> {
        let id = request.into_inner().id;
        let store = lock(&self.store)?;
        Ok(Response::new(grp::delete_group(&store, id)?))
    }
    async fn reorder_groups(&self, request: Request<pb::ReorderGroupsRequest>) -> Result<Response<pb::Empty>, Status> {
        let ids = request.into_inner().ordered_ids;
        let store = lock(&self.store)?;
        Ok(Response::new(grp::reorder_groups(&store, &ids)?))
    }
    async fn import_content(&self, request: Request<pb::ImportContentRequest>) -> Result<Response<pb::ImportContentResponse>, Status> {
        let r = request.into_inner();
        let store = lock(&self.store)?;
        Ok(Response::new(io_import_content(&store, &r)))
    }
    async fn export_links(&self, request: Request<pb::ExportLinksRequest>) -> Result<Response<pb::ExportLinksResponse>, Status> {
        let r = request.into_inner();
        let store = lock(&self.store)?;
        Ok(Response::new(io_export_links(&store, &r)?))
    }
    async fn move_profiles(&self, _: Request<pb::MoveProfilesRequest>) -> Result<Response<pb::Empty>, Status> { Err(unimpl("move_profiles")) }
    async fn clone_profiles(&self, _: Request<pb::CloneProfilesRequest>) -> Result<Response<pb::CloneProfilesResponse>, Status> { Err(unimpl("clone_profiles")) }
    async fn remove_unavailable_profiles(&self, _: Request<pb::RemoveUnavailableProfilesRequest>) -> Result<Response<pb::RemoveUnavailableResponse>, Status> { Err(unimpl("remove_unavailable_profiles")) }
    async fn deduplicate_profiles(&self, _: Request<pb::DeduplicateProfilesRequest>) -> Result<Response<pb::DeduplicateResponse>, Status> { Err(unimpl("deduplicate_profiles")) }
    async fn set_profile_meta(&self, _: Request<pb::SetProfileMetaRequest>) -> Result<Response<pb::Profile>, Status> { Err(unimpl("set_profile_meta")) }
    async fn preview_custom_fields(&self, _: Request<pb::PreviewCustomFieldsRequest>) -> Result<Response<pb::PreviewCustomFieldsResponse>, Status> { Err(unimpl("preview_custom_fields")) }
    async fn confirm_custom_fields(&self, _: Request<pb::ConfirmCustomFieldsRequest>) -> Result<Response<pb::Profile>, Status> { Err(unimpl("confirm_custom_fields")) }
    async fn export_config(&self, _: Request<pb::ExportConfigRequest>) -> Result<Response<pb::ExportConfigResponse>, Status> { Err(unimpl("export_config")) }
    async fn stop_tests(&self, _: Request<pb::StopTestsRequest>) -> Result<Response<pb::Empty>, Status> { Err(unimpl("stop_tests")) }
    async fn clear_test_results(&self, _: Request<pb::ClearTestResultsRequest>) -> Result<Response<pb::Empty>, Status> { Err(unimpl("clear_test_results")) }
    async fn resolve_domains(&self, _: Request<pb::ResolveDomainsRequest>) -> Result<Response<pb::ResolveDomainsResponse>, Status> { Err(unimpl("resolve_domains")) }

    type TestLatencyStream = tokio_stream::wrappers::ReceiverStream<Result<pb::LatencyResult, Status>>;
    async fn test_latency(&self, _: Request<pb::TestLatencyRequest>) -> Result<Response<Self::TestLatencyStream>, Status> { Err(unimpl("test_latency")) }
}
