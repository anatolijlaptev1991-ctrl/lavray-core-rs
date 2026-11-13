// SPDX-License-Identifier: GPL-3.0-only

//! Тесты SettingsService (волна 6): каталог, чтение/запись/сброс, валидация
//! неизвестных ключей, aggregated-флаги перезапуска.

use lavray_api::SettingsServiceImpl;
use lavray_proto::v1 as pb;
use lavray_proto::v1::settings_service_server::SettingsService;
use lavray_store::Store;
use std::sync::{Arc, Mutex};
use tonic::Request;

fn service() -> SettingsServiceImpl {
    let store = Store::open_memory().unwrap();
    SettingsServiceImpl::new(Arc::new(Mutex::new(store)))
}

fn sv_int(i: i64) -> pb::SettingValue {
    pb::SettingValue {
        value: Some(pb::setting_value::Value::IntValue(i)),
    }
}

#[tokio::test]
async fn describe_returns_catalog_and_groups() {
    let s = service();
    let resp = s
        .describe_settings(Request::new(pb::DescribeSettingsRequest {}))
        .await
        .unwrap();
    let inner = resp.into_inner();
    assert!(inner.descriptors.len() > 50, "каталог настроек");
    assert!(!inner.groups.is_empty());
    assert!(inner.descriptors.iter().any(|d| d.key == "inbound.port"));
}

#[tokio::test]
async fn set_get_roundtrip() {
    let s = service();
    let mut values = std::collections::HashMap::new();
    values.insert("inbound.port".to_string(), sv_int(2081));
    let resp = s
        .set_settings(Request::new(pb::SetSettingsRequest { values }))
        .await
        .unwrap();
    assert_eq!(resp.into_inner().accepted_keys, vec!["inbound.port"]);

    let resp = s
        .get_settings(Request::new(pb::GetSettingsRequest {
            keys: vec!["inbound.port".into()],
        }))
        .await
        .unwrap();
    let v = &resp.into_inner().values["inbound.port"];
    assert!(matches!(
        v.value,
        Some(pb::setting_value::Value::IntValue(2081))
    ));
}

#[tokio::test]
async fn set_unknown_key_rejected() {
    let s = service();
    let mut values = std::collections::HashMap::new();
    values.insert("no.such.key".to_string(), sv_int(1));
    let err = s
        .set_settings(Request::new(pb::SetSettingsRequest { values }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn set_internal_key_rejected() {
    let s = service();
    let mut values = std::collections::HashMap::new();
    values.insert("update.root_version".to_string(), sv_int(1));
    let err = s
        .set_settings(Request::new(pb::SetSettingsRequest { values }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn set_profile_restart_flag() {
    let s = service();
    let mut values = std::collections::HashMap::new();
    values.insert("inbound.port".to_string(), sv_int(2082));
    let resp = s
        .set_settings(Request::new(pb::SetSettingsRequest { values }))
        .await
        .unwrap();
    assert!(
        resp.into_inner().needs_profile_restart,
        "inbound.port требует перезапуска профиля"
    );
}

#[tokio::test]
async fn reset_restores_default() {
    let s = service();
    let mut values = std::collections::HashMap::new();
    values.insert("inbound.port".to_string(), sv_int(9999));
    s.set_settings(Request::new(pb::SetSettingsRequest { values }))
        .await
        .unwrap();
    s.reset_settings(Request::new(pb::ResetSettingsRequest {
        keys: vec!["inbound.port".into()],
    }))
    .await
    .unwrap();
    let resp = s
        .get_settings(Request::new(pb::GetSettingsRequest {
            keys: vec!["inbound.port".into()],
        }))
        .await
        .unwrap();
    let v = &resp.into_inner().values["inbound.port"];
    assert!(matches!(
        v.value,
        Some(pb::setting_value::Value::IntValue(2080))
    ));
}
