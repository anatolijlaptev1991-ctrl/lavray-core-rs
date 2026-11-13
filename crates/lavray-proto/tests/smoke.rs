// SPDX-License-Identifier: GPL-3.0-only

//! Smoke-тесты сгенерированного контракта (волна 6): prost round-trip сообщений
//! и наличие всех 15 сервисов. Контракт — proto/lavray.proto.

use lavray_proto::v1::{ConnectRequest, GetProfileRequest, Profile};
use prost::Message;

#[test]
fn get_profile_request_roundtrip() {
    let req = GetProfileRequest { id: 42 };
    let bytes = req.encode_to_vec();
    let back = GetProfileRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(back.id, 42);
}

#[test]
fn profile_roundtrip() {
    let p = Profile {
        id: 1,
        group_id: 2,
        name: "Test".into(),
        address: "h.com".into(),
        port: 443,
        ..Default::default()
    };
    let bytes = p.encode_to_vec();
    let back = Profile::decode(bytes.as_slice()).unwrap();
    assert_eq!(back, p);
}

#[test]
fn connect_request_optional_profile_id() {
    let req = ConnectRequest {
        profile_id: Some(7),
        ..Default::default()
    };
    let bytes = req.encode_to_vec();
    let back = ConnectRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(back.profile_id, Some(7));
}

/// Compile-time проверка: все 15 сервисов сгенерированы как server-трейты.
/// Если хотя бы один трейт отсутствует — тест не скомпилируется.
#[test]
fn all_services_present() {
    use lavray_proto::v1::{
        backup_service_server::BackupService, connection_service_server::ConnectionService,
        core_service_server::CoreService, diagnostics_service_server::DiagnosticsService,
        dns_service_server::DnsService, gateway_service_server::GatewayService,
        log_service_server::LogService, migration_service_server::MigrationService,
        profile_service_server::ProfileService, routing_service_server::RoutingService,
        settings_service_server::SettingsService, stats_service_server::StatsService,
        subscription_service_server::SubscriptionService, update_service_server::UpdateService,
        web_session_service_server::WebSessionService,
    };
    #[allow(dead_code)]
    fn require_all<T>()
    where
        T: CoreService
            + ProfileService
            + SubscriptionService
            + RoutingService
            + DnsService
            + SettingsService
            + LogService
            + StatsService
            + ConnectionService
            + DiagnosticsService
            + GatewayService
            + UpdateService
            + WebSessionService
            + BackupService
            + MigrationService,
    {
    }
}
