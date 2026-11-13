// SPDX-License-Identifier: GPL-3.0-only

//! Тесты StreamSettings: канонический JSON round-trip, omitempty, is_internal_full.

use lavray_model::{is_internal_full, CustomDetail, Detail, Profile, ProfileType, StreamSettings};

#[test]
fn stream_round_trip() {
    let p = Profile {
        r#type: ProfileType::VMess,
        address: "h".into(),
        port: 443,
        stream: Some(StreamSettings {
            network: "ws".into(),
            path: "/path?ed=2048".into(),
            host: "example.com".into(),
            security: "tls".into(),
            sni: "example.com".into(),
            alpn: "h2,http/1.1".into(),
            utls_fingerprint: "chrome".into(),
            packet_encoding: "xudp".into(),
            multiplex: 1,
            ws_early_data_max: 2048,
            ..Default::default()
        }),
        ..Default::default()
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: Profile = serde_json::from_str(&json).unwrap();
    assert_eq!(back.stream, p.stream);
}

#[test]
fn stream_omitempty_absent_when_none() {
    let p = Profile {
        r#type: ProfileType::Socks,
        ..Default::default()
    };
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains("\"stream\""));
}

#[test]
fn stream_empty_fields_skipped() {
    let s = StreamSettings {
        network: "tcp".into(),
        ..Default::default()
    };
    let json = serde_json::to_string(&s).unwrap();
    // Только network; пустые строки/нули/bool не эмитятся.
    assert_eq!(json, r#"{"network":"tcp"}"#);
}

#[test]
fn stream_reality_fields_round_trip() {
    let s = StreamSettings {
        security: "reality".into(),
        reality_public_key: "pbk".into(),
        reality_short_id: "sid".into(),
        reality_spx: "/".into(),
        ..Default::default()
    };
    let back: StreamSettings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(back, s);
}

#[test]
fn internal_full_detection() {
    let mut p = Profile {
        r#type: ProfileType::CustomConfig,
        detail: Some(Detail::Custom(CustomDetail {
            core: "internal-full".into(),
            full_config_json: "{}".into(),
            ..Default::default()
        })),
        ..Default::default()
    };
    assert!(is_internal_full(&p));
    // core != internal-full → не internal-full.
    if let Some(Detail::Custom(d)) = &mut p.detail {
        d.core = "internal".into();
    }
    assert!(!is_internal_full(&p));
    // Другой тип → не internal-full.
    p.r#type = ProfileType::CustomOutbound;
    if let Some(Detail::Custom(d)) = &mut p.detail {
        d.core = "internal-full".into();
    }
    assert!(!is_internal_full(&p));
}
