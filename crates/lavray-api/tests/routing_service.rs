// SPDX-License-Identifier: GPL-3.0-only

//! Тесты RoutingService (волна 6, порт Go preset_service_test.go): копия
//! builtin, правка с конфликтом ревизий, удаление (builtin отказ, активный →
//! global), сброс копии к источнику, активация и активный набор.

use lavray_api::RoutingServiceImpl;
use lavray_proto::v1 as pb;
use lavray_proto::v1::routing_service_server::RoutingService;
use lavray_store::Store;
use std::sync::{Arc, Mutex};
use tonic::{Code, Request, Status};

fn service() -> RoutingServiceImpl {
    let store = Store::open_memory().unwrap();
    RoutingServiceImpl::new(Arc::new(Mutex::new(store)))
}

fn code_of(err: &Status) -> Code {
    err.code()
}

#[tokio::test]
async fn list_contains_builtin_and_active_default() {
    let s = service();
    let r = s
        .list_presets(Request::new(pb::ListPresetsRequest {}))
        .await
        .unwrap()
        .into_inner();
    // builtin-наборы (6) + ни одного пользовательского; активный — global.
    assert_eq!(r.presets.len(), 6, "6 builtin: {r:?}");
    assert_eq!(r.active_preset_id, "global");
    assert!(r.presets.iter().any(|p| p.id == "lav-ru" && p.builtin));
    // DisplayName builtin — ключ локализации.
    assert_eq!(
        r.presets
            .iter()
            .find(|p| p.id == "lav-ru")
            .unwrap()
            .display_name,
        "preset.lav-ru"
    );
}

#[tokio::test]
async fn create_copy_of_builtin_tracks_source() {
    let s = service();
    let cp = s
        .create_preset(Request::new(pb::CreatePresetRequest {
            builtin_source_id: Some("lav-ru".into()),
            preset: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(cp.id.starts_with("custom:"));
    assert!(!cp.builtin);
    assert_eq!(cp.revision, 1);
    assert_eq!(cp.builtin_source_id, "lav-ru");
    assert!(cp.builtin_source_revision > 0);
    assert!(cp.display_name.ends_with(" (copy)"), "{}", cp.display_name);
    // Списки — от источника.
    let list = s
        .list_presets(Request::new(pb::ListPresetsRequest {}))
        .await
        .unwrap()
        .into_inner();
    let src = list.presets.iter().find(|p| p.id == "lav-ru").unwrap();
    assert_eq!(cp.direct_domain.len(), src.direct_domain.len());
    // Ровно одно из двух — INVALID_ARGUMENT.
    let err = s
        .create_preset(Request::new(pb::CreatePresetRequest {
            builtin_source_id: Some("lav-ru".into()),
            preset: Some(pb::RoutingPreset::default()),
        }))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Code::InvalidArgument);
}

#[tokio::test]
async fn create_from_values_mints_custom_id() {
    let s = service();
    let made = s
        .create_preset(Request::new(pb::CreatePresetRequest {
            builtin_source_id: None,
            preset: Some(pb::RoutingPreset {
                display_name: "My Set".into(),
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(made.id, "custom:my-set");
    assert_eq!(made.revision, 1);
}

#[tokio::test]
async fn update_conflict_and_success() {
    let s = service();
    let cp = s
        .create_preset(Request::new(pb::CreatePresetRequest {
            builtin_source_id: Some("global".into()),
            preset: None,
        }))
        .await
        .unwrap()
        .into_inner();
    // Устаревшая ревизия — ABORTED.
    let mut edited = cp.clone();
    edited.proxy_domain = vec!["example.org".into()];
    let err = s
        .update_preset(Request::new(pb::UpdatePresetRequest {
            preset: Some(edited.clone()),
            expected_revision: 999,
        }))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Code::Aborted);
    // Верный апдейт: ревизия +1.
    let up = s
        .update_preset(Request::new(pb::UpdatePresetRequest {
            preset: Some(edited),
            expected_revision: cp.revision,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(up.new_revision, 2);
    assert_eq!(
        up.preset.as_ref().unwrap().proxy_domain,
        vec!["example.org".to_string()]
    );
}

#[tokio::test]
async fn delete_builtin_rejected_unknown_not_found() {
    let s = service();
    for id in ["lav-ru", "global", "all-direct"] {
        let err = s
            .delete_preset(Request::new(pb::DeletePresetRequest { id: id.into() }))
            .await
            .unwrap_err();
        assert_eq!(code_of(&err), Code::FailedPrecondition, "{id}");
    }
    let err = s
        .delete_preset(Request::new(pb::DeletePresetRequest {
            id: "custom:none".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Code::NotFound);
}

#[tokio::test]
async fn reset_builtin_restores_lists_keeps_name() {
    let s = service();
    let mut cp = s
        .create_preset(Request::new(pb::CreatePresetRequest {
            builtin_source_id: Some("lav-ru".into()),
            preset: None,
        }))
        .await
        .unwrap()
        .into_inner();
    // Правка: очистить прямые домены, сменить имя.
    cp.direct_domain.clear();
    cp.display_name = "Мой набор".into();
    let up = s
        .update_preset(Request::new(pb::UpdatePresetRequest {
            preset: Some(cp.clone()),
            expected_revision: cp.revision,
        }))
        .await
        .unwrap()
        .into_inner();
    let edited = up.preset.unwrap();
    assert_eq!(edited.direct_domain, [] as [std::string::String; 0]);
    assert_eq!(edited.display_name, "Мой набор");
    // Сброс: списки от источника, имя сохранено, ревизия выросла.
    let reset = s
        .reset_builtin_preset(Request::new(pb::ResetBuiltinPresetRequest {
            id: edited.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    let src = s
        .get_preset(Request::new(pb::GetPresetRequest {
            id: "lav-ru".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reset.direct_domain.len(), src.direct_domain.len());
    assert_eq!(reset.display_name, "Мой набор");
    assert_eq!(reset.revision, edited.revision + 1);
}
