// SPDX-License-Identifier: GPL-3.0-only

//! Тесты RoutingService: активация/удаление активного/сброс копии (волна 6,
//! продолжение routing_service.rs — трещотка размеров).

use lavray_api::RoutingServiceImpl;
use lavray_proto::v1 as pb;
use lavray_proto::v1::routing_service_server::RoutingService;
use lavray_store::Store;
use std::sync::{Arc, Mutex};
use tonic::{Code, Request, Status};

fn code_of(err: &Status) -> Code {
    err.code()
}

fn service() -> RoutingServiceImpl {
    let store = Store::open_memory().unwrap();
    RoutingServiceImpl::new(Arc::new(Mutex::new(store)))
}

#[tokio::test]
async fn delete_active_switches_to_global() {
    let s = service();
    let cp = s
        .create_preset(Request::new(pb::CreatePresetRequest {
            builtin_source_id: Some("global".into()),
            preset: None,
        }))
        .await
        .unwrap()
        .into_inner();
    s.activate_preset(Request::new(pb::ActivatePresetRequest {
        id: cp.id.clone(),
    }))
    .await
    .unwrap();
    let active = s
        .get_active_preset(Request::new(pb::GetActivePresetRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(active.id, cp.id);
    // Удаление активного — активным становится global.
    let del = s
        .delete_preset(Request::new(pb::DeletePresetRequest { id: cp.id.clone() }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(del.new_active_id, "global");
    let list = s
        .list_presets(Request::new(pb::ListPresetsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(list.presets.len(), 6, "пользовательский удалён");
    assert_eq!(list.active_preset_id, "global");
    // id освобождается.
    let again = s
        .create_preset(Request::new(pb::CreatePresetRequest {
            builtin_source_id: Some("global".into()),
            preset: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.id, cp.id);
}

#[tokio::test]
async fn activate_unknown_and_active_or_global() {
    let s = service();
    let err = s
        .activate_preset(Request::new(pb::ActivatePresetRequest {
            id: "custom:gone".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Code::NotFound);
    // Активный с несуществующим id (правка данных) — работает global.
    let active = s
        .get_active_preset(Request::new(pb::GetActivePresetRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(active.id, "global");
}

#[tokio::test]
async fn source_updated_flag_after_revision_gap() {
    // Копия с ревизией 1 от источника ревизии 3+ — source_updated = true
    // (только для builtin-источников с большей ревизией).
    let s = service();
    let cp = s
        .create_preset(Request::new(pb::CreatePresetRequest {
            builtin_source_id: Some("lav-ru".into()),
            preset: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let list = s
        .list_presets(Request::new(pb::ListPresetsRequest {}))
        .await
        .unwrap()
        .into_inner();
    let mine = list.presets.iter().find(|p| p.id == cp.id).unwrap();
    // lav-ru rev 3 → копия source_revision 3 — флага нет.
    assert!(!mine.source_updated);
}
