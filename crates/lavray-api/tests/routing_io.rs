// SPDX-License-Identifier: GPL-3.0-only

//! Тесты обмена наборами файлом (порт Go preset_exchange_test.go): экспорт
//! builtin и копии, импорт LAVRay-файла — всегда новый набор, id из файла не
//! занимается, формат-детект отклоняет мусор, лимит размера.

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
async fn export_builtin_suggests_id_name() {
    let s = service();
    let r = s
        .export_preset(Request::new(pb::ExportPresetRequest {
            id: "lav-ru".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.suggested_name, "lav-ru");
    assert!(r.json.contains("\"id\": \"lav-ru\""));
    assert!(
        r.json.ends_with('\n'),
        "JSON заканчивается переводом строки"
    );
    // Отсутствующий — NOT_FOUND.
    let err = s
        .export_preset(Request::new(pb::ExportPresetRequest {
            id: "custom:none".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Code::NotFound);
}

#[tokio::test]
async fn export_custom_slug_name() {
    let s = service();
    let cp = s
        .create_preset(Request::new(pb::CreatePresetRequest {
            builtin_source_id: Some("global".into()),
            preset: None,
        }))
        .await
        .unwrap()
        .into_inner();
    // Имя «Global (copy)» → slug global-copy.
    let r = s
        .export_preset(Request::new(pb::ExportPresetRequest { id: cp.id.clone() }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.suggested_name, "global-copy");
}

#[tokio::test]
async fn import_lavray_creates_new_custom_preset() {
    let s = service();
    let exported = s
        .export_preset(Request::new(pb::ExportPresetRequest {
            id: "lav-ru".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .json;
    let imported = s
        .import_preset(Request::new(pb::ImportPresetRequest { json: exported }))
        .await
        .unwrap()
        .into_inner();
    let p = imported.preset.unwrap();
    // Новый id: файл не может занять id встроенного набора.
    assert_ne!(p.id, "lav-ru");
    assert!(p.id.starts_with("custom:"));
    assert!(!p.builtin);
    assert_eq!(p.revision, 1);
    assert_eq!(imported.warnings, [] as [std::string::String; 0]);
    // Второй импорт того же файла — снова новый id (-2).
    let exported2 = s
        .export_preset(Request::new(pb::ExportPresetRequest {
            id: "lav-ru".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .json;
    let second = s
        .import_preset(Request::new(pb::ImportPresetRequest { json: exported2 }))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(second.preset.unwrap().id, p.id);
}

#[tokio::test]
async fn import_rejects_garbage_and_oversize() {
    let s = service();
    let err = s
        .import_preset(Request::new(pb::ImportPresetRequest {
            json: "not json".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Code::InvalidArgument);
    // Объект без routing и без ключей NekoRay.
    let err = s
        .import_preset(Request::new(pb::ImportPresetRequest {
            json: "{\"a\":1}".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Code::InvalidArgument);
    // Больше 1 МиБ.
    let big = format!("{{\"routing\":{{}},\"pad\":\"{}\"}}", "x".repeat(1 << 21));
    let err = s
        .import_preset(Request::new(pb::ImportPresetRequest { json: big }))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Code::ResourceExhausted);
    // Неподдерживаемая версия схемы.
    let err = s
        .import_preset(Request::new(pb::ImportPresetRequest {
            json: "{\"version\":99,\"routing\":{}}".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Code::InvalidArgument);
}

#[tokio::test]
async fn corrupted_meta_is_data_loss() {
    let store = Store::open_memory().unwrap();
    store
        .set_meta("routing.custom_presets", "{не json")
        .unwrap();
    let s = RoutingServiceImpl::new(Arc::new(Mutex::new(store)));
    let err = s
        .list_presets(Request::new(pb::ListPresetsRequest {}))
        .await
        .unwrap_err();
    assert_eq!(
        code_of(&err),
        Code::DataLoss,
        "повреждённая запись не затирается молча"
    );
}
