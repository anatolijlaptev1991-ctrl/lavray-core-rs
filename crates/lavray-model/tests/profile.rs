// SPDX-License-Identifier: GPL-3.0-only

//! Тесты модели: канонический JSON Profile (detail сливается по type),
//! round-trip, типоспецифичные detail, Group.

use lavray_model::{
    Detail, Group, GroupKind, Hysteria2Detail, Profile, ProfileType, TestResult, TrojanVlessDetail,
    VMessDetail,
};
use serde_json::Value;

fn vmess_profile() -> Profile {
    Profile {
        id: 1,
        group_id: 2,
        r#type: ProfileType::VMess,
        name: "Test VMess".into(),
        address: "example.com".into(),
        port: 443,
        detail: Some(Detail::VMess(VMessDetail {
            uuid: "uuid-123".into(),
            alter_id: 0,
            security: "auto".into(),
        })),
        ..Default::default()
    }
}

#[test]
fn profile_type_snake_case() {
    assert_eq!(
        serde_json::to_value(ProfileType::Hysteria2).unwrap(),
        "hysteria2"
    );
    assert_eq!(
        serde_json::to_value(ProfileType::CustomOutbound).unwrap(),
        "custom_outbound"
    );
    assert_eq!(serde_json::to_value(ProfileType::VMess).unwrap(), "vmess");
}

#[test]
fn detail_merged_at_top_level() {
    let p = vmess_profile();
    let v = serde_json::to_value(&p).unwrap();
    // detail — вложенный объект под ключом "detail", без тега варианта.
    assert_eq!(v["detail"]["uuid"], "uuid-123");
    assert_eq!(v["detail"]["security"], "auto");
    assert_eq!(v["type"], "vmess");
    assert!(v.get("Detail").is_none(), "не должно быть PascalCase");
}

#[test]
fn profile_round_trip() {
    let p = vmess_profile();
    let json = serde_json::to_string(&p).unwrap();
    let back: Profile = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn detail_none_omitted() {
    let p = Profile {
        r#type: ProfileType::Socks,
        ..Default::default()
    };
    let v = serde_json::to_value(&p).unwrap();
    assert!(v.get("detail").is_none());
}

#[test]
fn trojan_vless_detail_by_type() {
    for t in [ProfileType::Trojan, ProfileType::Vless] {
        let p = Profile {
            r#type: t,
            detail: Some(Detail::TrojanVless(TrojanVlessDetail {
                password: "secret".into(),
                flow: "xtls-rprx-vision".into(),
            })),
            ..Default::default()
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
        assert!(matches!(back.detail, Some(Detail::TrojanVless(_))));
    }
}

#[test]
fn hysteria2_detail_round_trip() {
    let p = Profile {
        r#type: ProfileType::Hysteria2,
        detail: Some(Detail::Hysteria2(Hysteria2Detail {
            password: "pw".into(),
            server_ports: "443:8443".into(),
            hop_interval: "30s".into(),
            allow_insecure: true,
            ..Default::default()
        })),
        ..Default::default()
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: Profile = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
    if let Some(Detail::Hysteria2(d)) = back.detail {
        assert_eq!(d.server_ports, "443:8443");
        assert_eq!(d.hop_interval, "30s");
        assert!(d.allow_insecure);
    } else {
        panic!("ожидался Hysteria2 detail");
    }
}

#[test]
fn test_result_latency_semantics() {
    // None = не тестировали, <0 = unavailable, >0 = латентность.
    let t = TestResult {
        latency_ms: Some(-1),
        ..Default::default()
    };
    let v = serde_json::to_value(&t).unwrap();
    assert_eq!(v["latency_ms"], -1);
    let empty = TestResult::default();
    let v = serde_json::to_value(&empty).unwrap();
    assert!(v.get("latency_ms").is_none());
}

#[test]
fn omitempty_fields_skipped() {
    let p = Profile {
        r#type: ProfileType::Socks,
        ..Default::default()
    };
    let v = serde_json::to_value(&p).unwrap();
    assert!(v.get("favorite").is_none());
    assert!(v.get("tags").is_none());
    assert!(v.get("notes").is_none());
    assert!(v.get("geo").is_none());
    // traffic всегда присутствует (не omitempty в Go).
    assert!(v.get("traffic").is_some());
}

#[test]
fn group_kind_numeric() {
    // Паритет Go model.GroupKind int (P2-12): JSON — число 1/2.
    assert_eq!(serde_json::to_value(GroupKind::Basic).unwrap(), 1);
    assert_eq!(serde_json::to_value(GroupKind::Subscription).unwrap(), 2);
    let back: GroupKind = serde_json::from_value(serde_json::json!(2)).unwrap();
    assert_eq!(back, GroupKind::Subscription);
}

#[test]
fn test_result_always_emitted() {
    // Go test_result,omitempty не опускает структуры → всегда {} (P2-13).
    let p = Profile::default();
    let v = serde_json::to_value(&p).unwrap();
    assert_eq!(v.get("test_result"), Some(&serde_json::json!({})));
}

#[test]
fn group_round_trip() {
    let g = Group {
        id: 5,
        name: "Sub".into(),
        kind: GroupKind::Subscription,
        subscription_url: "https://example.com/sub".into(),
        ..Default::default()
    };
    let json = serde_json::to_string(&g).unwrap();
    let back: Group = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

#[test]
fn deserialize_rejects_non_object() {
    let r: Result<Profile, _> = serde_json::from_str("[]");
    assert!(r.is_err());
}

#[test]
fn detail_value_is_object() {
    let d = Detail::VMess(VMessDetail {
        uuid: "u".into(),
        ..Default::default()
    });
    let v = d.to_value();
    assert!(v.is_object());
    assert_eq!(v["uuid"], "u");
}

#[test]
fn unknown_detail_fields_ignored() {
    // Лишние поля в detail не ломают разбор (forward-compat).
    let json = r#"{"id":1,"group_id":0,"type":"vmess","name":"n","address":"a","port":1,"traffic":{"uplink_bytes":0,"downlink_bytes":0},"detail":{"uuid":"u","extra":"x"}}"#;
    let p: Profile = serde_json::from_str(json).unwrap();
    assert!(matches!(p.detail, Some(Detail::VMess(_))));
}

#[test]
fn port_and_address_preserved() {
    let p = vmess_profile();
    let v: Value = serde_json::to_value(&p).unwrap();
    assert_eq!(v["port"], 443);
    assert_eq!(v["address"], "example.com");
}
