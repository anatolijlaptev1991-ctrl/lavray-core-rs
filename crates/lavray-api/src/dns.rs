// SPDX-License-Identifier: GPL-3.0-only

//! DnsService (волна 6.5, порт Go api/routing_settings_service.go):
//! GetDns — снимок DNS активного пресета + переопределение-карточка;
//! SetDns — карточка для АКТИВНОГО пресета (T-31, «Авто» = сброс);
//! ValidateDnsJson — Format/Validate редактора DNS-объекта (FR-UI-149).

#![allow(clippy::result_large_err)] // tonic::Status велик по природе контракта

use crate::dns_choice::{DnsChoice, active_choice, active_dns, save_choice};
use crate::preset_convert_dns::{strategy_from_proto, strategy_to_proto};
use lavray_proto::v1 as pb;
use lavray_proto::v1::dns_service_server::DnsService;
use lavray_store::Store;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

use crate::preset_active::{active_preset_id, drop_dns_choice};

/// Реализация DnsService поверх общего хранилища.
pub struct DnsServiceImpl {
    store: Arc<Mutex<Store>>,
}

impl DnsServiceImpl {
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

/// advanced-DNS обязан содержать сервер с tag dns-direct (LNB-08).
pub(super) fn dns_object_has_direct(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    obj.get("servers")
        .and_then(|s| s.as_array())
        .is_some_and(|servers| {
            servers
                .iter()
                .any(|srv| srv.get("tag").and_then(|t| t.as_str()) == Some("dns-direct"))
        })
}

impl DnsServiceImpl {
    /// Снимок действующего DNS (пресет + переопределение).
    fn current_dns(st: &Store) -> pb::DnsSettings {
        let mut out = pb::DnsSettings {
            mode: pb::dns_settings::Mode::Simple as i32,
            ..Default::default()
        };
        // DNS активного пресета (или дефолт).
        let dns = active_dns(st);
        if dns.mode == "advanced" {
            out.mode = pb::dns_settings::Mode::Advanced as i32;
        }
        out.remote_dns = Some(dns.remote_dns.clone());
        out.direct_dns = Some(dns.direct_dns.clone());
        out.routing_enabled = dns.routing_enabled;
        if !dns.advanced_json.is_empty() {
            out.advanced_json = Some(dns.advanced_json.clone());
        }
        if !dns.remote_query_strategy.is_empty() {
            out.remote_query_strategy = Some(strategy_to_proto(&dns.remote_query_strategy));
        }
        // Переопределение-карточка активного пресета.
        if let Some(choice) = active_choice(st) {
            out.choice = Some(choice);
        } else {
            out.choice = Some("auto".into());
        }
        out
    }
}

#[tonic::async_trait]
impl DnsService for DnsServiceImpl {
    async fn get_dns(
        &self,
        _request: Request<pb::GetDnsRequest>,
    ) -> Result<Response<pb::DnsSettings>, Status> {
        let st = lock(&self.store)?;
        Ok(Response::new(Self::current_dns(&st)))
    }

    async fn set_dns(
        &self,
        request: Request<pb::SetDnsRequest>,
    ) -> Result<Response<pb::SetDnsResponse>, Status> {
        let m = request.into_inner();
        let Some(dns) = m.dns else {
            return Err(Status::invalid_argument("dns обязателен"));
        };
        // advanced: JSON-объект с dns-direct.
        if dns.mode == pb::dns_settings::Mode::Advanced as i32
            && let Some(json) = dns.advanced_json.as_deref().filter(|s| !s.is_empty())
        {
            let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(json)
                .map_err(|e| {
                    Status::invalid_argument(format!("advanced_json: невалидный JSON: {e}"))
                })?;
            if !dns_object_has_direct(&obj) {
                return Err(Status::invalid_argument(
                    "advanced_json: нужен сервер с tag \"dns-direct\" (LNB-08)",
                ));
            }
        }
        // Карточка: пусто-remote → auto; иначе custom с адресом.
        let remote = dns.remote_dns.clone().unwrap_or_default();
        let choice = if remote.is_empty() {
            "auto".to_string()
        } else {
            "custom".to_string()
        };
        let active = {
            let st = lock(&self.store)?;
            active_preset_id(&st)
        };
        let st = lock(&self.store)?;
        if choice == "auto" {
            drop_dns_choice(&st, &active)?;
        } else {
            save_choice(
                &st,
                &active,
                &DnsChoice {
                    choice,
                    remote_dns: remote,
                    remote_query_strategy: dns
                        .remote_query_strategy
                        .map_or_default(strategy_from_proto),
                },
            )?;
        }
        Ok(Response::new(pb::SetDnsResponse {
            needs_profile_restart: false,      // движок — волна 7g; idle-паритет
            new_revision: m.expected_revision, // конфликт — UpdatePreset-путём
            applied: Some(Self::current_dns(&st)),
        }))
    }

    async fn validate_dns_json(
        &self,
        request: Request<pb::ValidateDnsJsonRequest>,
    ) -> Result<Response<pb::ValidateDnsJsonResponse>, Status> {
        let raw = request.into_inner().json;
        Ok(super::dns_validate::validate(&raw))
    }
}
