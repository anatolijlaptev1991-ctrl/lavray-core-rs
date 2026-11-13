// SPDX-License-Identifier: GPL-3.0-only

//! SettingsService (волна 6, порт Go api/settings_service.go): каталог ключей,
//! чтение/запись/сброс настроек поверх store. Валидация: неизвестный/служебный
//! ключ → INVALID_ARGUMENT; aggregated-флаги перезапуска (FR-UI-062/063/064).

use crate::convert::{descriptor_to_proto, json_to_setting_value, setting_value_to_json};
use lavray_model::{setting_descriptors, SETTING_GROUPS};
use lavray_proto::v1 as pb;
use lavray_proto::v1::settings_service_server::SettingsService;
use lavray_store::Store;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

/// Реализация SettingsService поверх хранилища.
pub struct SettingsServiceImpl {
    store: Arc<Mutex<Store>>,
}

impl SettingsServiceImpl {
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
impl SettingsService for SettingsServiceImpl {
    async fn describe_settings(
        &self,
        _request: Request<pb::DescribeSettingsRequest>,
    ) -> Result<Response<pb::DescribeSettingsResponse>, Status> {
        let descriptors = setting_descriptors()
            .iter()
            .map(descriptor_to_proto)
            .collect();
        let groups = SETTING_GROUPS
            .iter()
            .map(|id| pb::SettingGroup {
                id: (*id).to_string(),
                name_key: format!("settings.group.{id}"),
            })
            .collect();
        Ok(Response::new(pb::DescribeSettingsResponse {
            descriptors,
            groups,
        }))
    }

    async fn get_settings(
        &self,
        request: Request<pb::GetSettingsRequest>,
    ) -> Result<Response<pb::GetSettingsResponse>, Status> {
        let keys = request.into_inner().keys;
        let store = lock(&self.store)?;
        let catalog = setting_descriptors();
        let wanted: Vec<String> = if keys.is_empty() {
            catalog
                .iter()
                .filter(|d| !d.internal)
                .map(|d| d.key.clone())
                .collect()
        } else {
            keys
        };
        let mut values = HashMap::new();
        for key in wanted {
            if let Some(v) = store
                .get_setting(&key)
                .map_err(|e| Status::internal(e.to_string()))?
            {
                values.insert(key, json_to_setting_value(&v));
            }
        }
        Ok(Response::new(pb::GetSettingsResponse { values }))
    }

    async fn set_settings(
        &self,
        request: Request<pb::SetSettingsRequest>,
    ) -> Result<Response<pb::SetSettingsResponse>, Status> {
        let values = request.into_inner().values;
        let catalog = setting_descriptors();
        // Неизвестный/служебный ключ → INVALID_ARGUMENT со списком.
        let mut unknown: Vec<String> = Vec::new();
        for key in values.keys() {
            let known = catalog.iter().any(|d| &d.key == key && !d.internal);
            if !known {
                unknown.push(key.clone());
            }
        }
        if !unknown.is_empty() {
            return Err(Status::invalid_argument(format!(
                "неизвестные или служебные ключи: {}",
                unknown.join(", ")
            )));
        }
        let store = lock(&self.store)?;
        let mut accepted = Vec::new();
        let mut needs_profile_restart = false;
        let mut needs_app_restart = false;
        for (key, sv) in &values {
            let json = setting_value_to_json(sv);
            store
                .set_setting(key, &json)
                .map_err(|e| Status::internal(e.to_string()))?;
            accepted.push(key.clone());
            if let Some(d) = catalog.iter().find(|d| &d.key == key) {
                needs_profile_restart |= d.requires_profile_restart;
                needs_app_restart |= d.requires_app_restart;
            }
        }
        Ok(Response::new(pb::SetSettingsResponse {
            accepted_keys: accepted,
            needs_profile_restart,
            needs_app_restart,
        }))
    }

    async fn reset_settings(
        &self,
        request: Request<pb::ResetSettingsRequest>,
    ) -> Result<Response<pb::SetSettingsResponse>, Status> {
        let keys = request.into_inner().keys;
        let catalog = setting_descriptors();
        let targets: Vec<&lavray_model::SettingDescriptor> = if keys.is_empty() {
            catalog.iter().filter(|d| !d.internal).collect()
        } else {
            catalog
                .iter()
                .filter(|d| keys.contains(&d.key) && !d.internal)
                .collect()
        };
        let store = lock(&self.store)?;
        let mut accepted = Vec::new();
        let mut needs_profile_restart = false;
        for d in targets {
            // Сброс к дефолту: записываем default_value_json (или удаляем).
            if d.default_value.is_empty() {
                store
                    .set_setting(&d.key, &serde_json::Value::Null)
                    .map_err(|e| Status::internal(e.to_string()))?;
            } else {
                let v: serde_json::Value = serde_json::from_str(&d.default_value)
                    .map_err(|e| Status::internal(e.to_string()))?;
                store
                    .set_setting(&d.key, &v)
                    .map_err(|e| Status::internal(e.to_string()))?;
            }
            accepted.push(d.key.clone());
            needs_profile_restart |= d.requires_profile_restart;
        }
        Ok(Response::new(pb::SetSettingsResponse {
            accepted_keys: accepted,
            needs_profile_restart,
            needs_app_restart: false,
        }))
    }

    type SubscribeSettingsStream =
        tokio_stream::wrappers::ReceiverStream<Result<pb::SettingsChanged, Status>>;

    async fn subscribe_settings(
        &self,
        _request: Request<pb::SubscribeSettingsRequest>,
    ) -> Result<Response<Self::SubscribeSettingsStream>, Status> {
        // Поток изменений — волна 6 (расширение): пока пустой канал.
        let (_tx, rx) = tokio::sync::mpsc::channel(16);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}
