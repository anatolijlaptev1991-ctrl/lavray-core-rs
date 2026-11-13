// SPDX-License-Identifier: GPL-3.0-only

//! Тесты ProfileService (волна 6): round-trip конверсий model↔proto для всех
//! Detail-типов, CRUD RPC поверх in-memory store.

use lavray_api::profile_convert::{profile_from_proto, profile_to_proto};
use lavray_api::ProfileServiceImpl;
use lavray_model::{self as m, Detail, Profile, ProfileType, StreamSettings};
use lavray_proto::v1 as pb;
use lavray_proto::v1::profile_service_server::ProfileService;
use lavray_store::{Store, DEFAULT_GROUP_ID};
use std::sync::{Arc, Mutex};
use tonic::Request;

fn service() -> ProfileServiceImpl {
    let store = Store::open_memory().unwrap();
    ProfileServiceImpl::new(Arc::new(Mutex::new(store)))
}

fn roundtrip(p: &Profile) -> Profile {
    profile_from_proto(&profile_to_proto(p))
}

#[test]
fn profile_socks_roundtrip() {
    let p = Profile {
        r#type: ProfileType::Socks,
        name: "N".into(),
        address: "h.com".into(),
        port: 1080,
        detail: Some(Detail::SocksHttp(m::SocksHttpDetail {
            proto: "socks5".into(),
            username: "u".into(),
            password: "p".into(),
        })),
        ..Default::default()
    };
    let back = roundtrip(&p);
    assert_eq!(back.r#type, ProfileType::Socks);
    assert_eq!(back.address, "h.com");
    assert_eq!(back.port, 1080);
    assert!(matches!(back.detail, Some(Detail::SocksHttp(d)) if d.username == "u"));
}

#[test]
fn profile_vmess_stream_reality_roundtrip() {
    let p = Profile {
        r#type: ProfileType::VMess,
        address: "h.com".into(),
        port: 443,
        stream: Some(StreamSettings {
            network: "ws".into(),
            security: "reality".into(),
            sni: "h.com".into(),
            reality_public_key: "KEY".into(),
            path: "/ws".into(),
            ..Default::default()
        }),
        detail: Some(Detail::VMess(m::VMessDetail {
            uuid: "uuid-1".into(),
            alter_id: 0,
            security: "auto".into(),
        })),
        ..Default::default()
    };
    let back = roundtrip(&p);
    let st = back.stream.unwrap();
    assert_eq!(st.network, "ws");
    assert_eq!(st.security, "reality");
    assert_eq!(st.reality_public_key, "KEY");
    assert!(matches!(back.detail, Some(Detail::VMess(d)) if d.uuid == "uuid-1"));
}

#[test]
fn profile_tuic_roundtrip() {
    let p = Profile {
        r#type: ProfileType::Tuic,
        address: "h.com".into(),
        port: 443,
        detail: Some(Detail::Tuic(m::TuicDetail {
            uuid: "u".into(),
            password: "p".into(),
            congestion_control: "bbr".into(),
            udp_relay_mode: "native".into(),
            zero_rtt_handshake: true,
            ..Default::default()
        })),
        ..Default::default()
    };
    let back = roundtrip(&p);
    assert!(
        matches!(back.detail, Some(Detail::Tuic(d)) if d.congestion_control == "bbr" && d.zero_rtt_handshake)
    );
}

#[test]
fn profile_chain_roundtrip() {
    let p = Profile {
        r#type: ProfileType::Chain,
        detail: Some(Detail::Chain(m::ChainDetail {
            profile_ids: vec![1, 2, 3],
        })),
        ..Default::default()
    };
    let back = roundtrip(&p);
    assert!(matches!(back.detail, Some(Detail::Chain(c)) if c.profile_ids == vec![1, 2, 3]));
}

#[test]
fn custom_fields_confirmed_computed_not_echoed() {
    // T-08B: флаг вычисляется по custom_hash; без хэша всегда false.
    let mut p = Profile {
        r#type: ProfileType::CustomOutbound,
        custom_outbound_json: "{\"a\":1}".into(),
        ..Default::default()
    };
    p.custom_hash = String::new();
    let proto = profile_to_proto(&p);
    assert!(!proto.custom_fields_confirmed);
    // Клиентское значение игнорируется при разборе.
    let mut echoed = profile_to_proto(&p);
    echoed.custom_fields_confirmed = true;
    assert!(!profile_from_proto(&echoed).custom_fields_confirmed);
}

#[tokio::test]
async fn crud_rpc_roundtrip() {
    let s = service();
    let mut p = pb::Profile {
        r#type: pb::ProfileType::Socks as i32,
        name: "Test".into(),
        address: "h.com".into(),
        port: 1080,
        group_id: DEFAULT_GROUP_ID,
        ..Default::default()
    };
    let created = s
        .create_profile(Request::new(pb::CreateProfileRequest {
            profile: Some(p.clone()),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(created.id > 0, "id назначен хранилищем");
    p.id = created.id;
    assert_eq!(created.name, "Test");

    let fetched = s
        .get_profile(Request::new(pb::GetProfileRequest { id: created.id }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.address, "h.com");

    let list = s
        .list_profiles(Request::new(pb::ListProfilesRequest {
            group_id: Some(DEFAULT_GROUP_ID),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(list.total, 1);

    p.name = "Renamed".into();
    let updated = s
        .update_profile(Request::new(pb::UpdateProfileRequest {
            profile: Some(p),
            update_mask: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.profile.unwrap().name, "Renamed");

    s.delete_profile(Request::new(pb::DeleteProfileRequest {
        ids: vec![created.id],
    }))
    .await
    .unwrap();
    let err = s
        .get_profile(Request::new(pb::GetProfileRequest { id: created.id }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn group_crud_rpc() {
    let s = service();
    let g = pb::Group {
        name: "My Group".into(),
        kind: pb::group::Kind::Subscription as i32,
        subscription_url: Some("https://example.com/sub".into()),
        ..Default::default()
    };
    let created = s
        .create_group(Request::new(pb::CreateGroupRequest { group: Some(g) }))
        .await
        .unwrap()
        .into_inner();
    assert!(created.id > 0);
    assert_eq!(created.kind, pb::group::Kind::Subscription as i32);

    let list = s
        .list_groups(Request::new(pb::ListGroupsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(list.groups.iter().any(|g| g.id == created.id));
}

#[tokio::test]
async fn import_content_parses_links() {
    let s = service();
    let resp = s
        .import_content(Request::new(pb::ImportContentRequest {
            content: "trojan://pw@h.com:443#T1\nsocks5://u:p@h.com:1080#S1\nмусор без схемы".into(),
            target_group_id: Some(DEFAULT_GROUP_ID),
            preview_only: Some(false),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.parsed_profiles.len(), 2, "2 валидных ссылки");
    assert_eq!(resp.added_profile_ids.len(), 2, "оба сохранены");
    assert_eq!(
        resp.kind,
        pb::import_content_response::ContentKind::ShareLinks as i32
    );
}

#[tokio::test]
async fn export_links_roundtrip() {
    let s = service();
    let imported = s
        .import_content(Request::new(pb::ImportContentRequest {
            content: "trojan://pw@h.com:443#T".into(),
            target_group_id: Some(DEFAULT_GROUP_ID),
            preview_only: Some(false),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    let resp = s
        .export_links(Request::new(pb::ExportLinksRequest {
            ids: imported.added_profile_ids.clone(),
            group_id: None,
            format: 0,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.links.len(), 1);
    assert!(resp.links[0].starts_with("trojan://"));
}
