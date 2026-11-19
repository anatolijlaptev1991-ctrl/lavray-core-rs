// SPDX-License-Identifier: GPL-3.0-only

//! ImportNekoRayRoute RPC и ImportPreset-NekoRay-ветка (волна 6.5):
//! RoutingBean → пользовательский набор, процессные правила, warnings.

use lavray_api::RoutingServiceImpl;
use lavray_proto::v1 as pb;
use lavray_proto::v1::routing_service_server::RoutingService;
use lavray_store::Store;
use std::sync::{Arc, Mutex};
use tonic::Request;

fn service() -> RoutingServiceImpl {
    let store = Store::open_memory().unwrap();
    RoutingServiceImpl::new(Arc::new(Mutex::new(store)))
}

#[tokio::test]
async fn import_neko_route_creates_custom_preset() {
    let s = service();
    let custom = serde_json::to_string(&serde_json::json!({
        "rules": [
            {"process_name": "game.exe", "outbound": "bypass"},
        ]
    }))
    .unwrap();
    let r = s
        .import_neko_ray_route(Request::new(pb::ImportNekoRayRouteRequest {
            nekobox_json: serde_json::to_string(&serde_json::json!({
                "direct_domain": "ya.ru # коммент
            vk.ru",
                "def_outbound": "direct",
                "domain_strategy": "UseIPv6",
                "custom": custom,
            }))
            .unwrap(),
            name: Some("My Neko Route".into()),
        }))
        .await
        .unwrap()
        .into_inner();
    let p = r.preset.unwrap();
    assert!(p.id.starts_with("custom:"));
    assert!(!p.builtin);
    assert_eq!(p.display_name, "My Neko Route");
    assert_eq!(p.default_outbound, 2); // direct
    assert_eq!(p.direct_domain, vec!["ya.ru".to_string(), "vk.ru".into()]);
    assert_eq!(p.process_rules.len(), 1); // *.exe → windows-only
    assert!(!r.warnings.is_empty(), "domain_strategy DROP → warning");
}
