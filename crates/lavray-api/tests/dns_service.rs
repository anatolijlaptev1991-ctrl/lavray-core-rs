// SPDX-License-Identifier: GPL-3.0-only

//! Тесты DnsService (волна 6.5): GetDns — DNS активного пресета с
//! дефолт-карточкой auto; SetDns — custom с адресом → карточка, «Авто»
//! (пустой remote) — сброс; ValidateDnsJson — servers/dns-direct/формат.

use lavray_api::DnsServiceImpl;
use lavray_proto::v1 as pb;
use lavray_proto::v1::dns_service_server::DnsService;
use lavray_store::Store;
use std::sync::{Arc, Mutex};
use tonic::Request;

fn service() -> DnsServiceImpl {
    let store = Store::open_memory().unwrap();
    DnsServiceImpl::new(Arc::new(Mutex::new(store)))
}

fn dns(choice_remote: Option<&str>) -> pb::DnsSettings {
    pb::DnsSettings {
        mode: pb::dns_settings::Mode::Simple as i32,
        remote_dns: choice_remote.map(str::to_string),
        ..Default::default()
    }
}

#[tokio::test]
async fn get_dns_defaults_auto_and_lavru_dns() {
    let s = service();
    let out = s
        .get_dns(Request::new(pb::GetDnsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(out.mode, pb::dns_settings::Mode::Simple as i32);
    assert_eq!(out.choice.as_deref(), Some("auto"));
    assert_eq!(
        out.remote_dns.as_deref(),
        Some("https://dns.google/dns-query")
    );
    assert_eq!(out.direct_dns.as_deref(), Some("local"));
}

#[tokio::test]
async fn set_dns_custom_then_auto_resets() {
    let s = service();
    // custom: непустой remote.
    let r = s
        .set_dns(Request::new(pb::SetDnsRequest {
            dns: Some(dns(Some("https://1.1.1.1/dns-query"))),
            expected_revision: 0,
        }))
        .await
        .unwrap()
        .into_inner();
    let applied = r.applied.unwrap();
    assert_eq!(applied.choice.as_deref(), Some("custom"));
    // «Авто»: пустой remote сбрасывает.
    s.set_dns(Request::new(pb::SetDnsRequest {
        dns: Some(dns(None)),
        expected_revision: 0,
    }))
    .await
    .unwrap();
    let out = s
        .get_dns(Request::new(pb::GetDnsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(out.choice.as_deref(), Some("auto"));
}

#[tokio::test]
async fn advanced_json_requires_dns_direct() {
    let s = service();
    let bad = pb::DnsSettings {
        mode: pb::dns_settings::Mode::Advanced as i32,
        advanced_json: Some(r#"{"servers":[{"tag":"x"}]}"#.into()),
        ..Default::default()
    };
    let err = s
        .set_dns(Request::new(pb::SetDnsRequest {
            dns: Some(bad),
            expected_revision: 0,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    let good = pb::DnsSettings {
        mode: pb::dns_settings::Mode::Advanced as i32,
        advanced_json: Some(r#"{"servers":[{"tag":"dns-direct","type":"local"}]}"#.into()),
        ..Default::default()
    };
    assert!(
        s.set_dns(Request::new(pb::SetDnsRequest {
            dns: Some(good),
            expected_revision: 0,
        }))
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn validate_dns_json_checks() {
    async fn call(json: &str) -> pb::ValidateDnsJsonResponse {
        let s2 = DnsServiceImpl::new(Arc::new(Mutex::new(Store::open_memory().unwrap())));
        s2.validate_dns_json(Request::new(pb::ValidateDnsJsonRequest {
            json: json.into(),
        }))
        .await
        .unwrap()
        .into_inner()
    }
    let _ = service();
    // Пустой.
    let r = call("").await;
    assert!(!r.valid);
    // Невалидный JSON.
    let r = call("{").await;
    assert!(!r.valid);
    // Нет servers.
    let r = call("{}").await;
    assert!(!r.valid);
    assert!(r.errors.iter().any(|e| e.contains("servers")));
    // Валидный с dns-direct: formatted отдаётся.
    let r = call(r#"{"servers":[{"tag":"dns-direct","type":"local"}]}"#).await;
    assert!(r.valid, "{:?}", r.errors);
    assert!(r.formatted.unwrap().contains("dns-direct"));
}
