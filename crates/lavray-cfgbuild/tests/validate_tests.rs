// SPDX-License-Identifier: GPL-3.0-only

//! Тесты валидации звена цепочки (validate_ent) и ошибок сборки Build.

use lavray_cfgbuild::validate::{unsupported_reason, validate_ent};
use lavray_cfgbuild::{build, BuildRequest};
use lavray_model::{CustomDetail, Detail, Profile, ProfileType, StreamSettings};

fn vmess_profile() -> Profile {
    Profile {
        r#type: ProfileType::VMess,
        address: "h".into(),
        port: 443,
        ..Default::default()
    }
}

#[test]
fn validate_empty_address() {
    let mut p = vmess_profile();
    p.address = "  ".into();
    assert!(validate_ent(&p).is_err());
}

#[test]
fn validate_bad_port() {
    let mut p = vmess_profile();
    p.port = 0;
    assert!(validate_ent(&p).is_err());
    p.port = 70000;
    assert!(validate_ent(&p).is_err());
}

#[test]
fn validate_reality_without_key() {
    let mut p = vmess_profile();
    p.stream = Some(StreamSettings {
        security: "reality".into(),
        ..Default::default()
    });
    assert!(validate_ent(&p).is_err());
}

#[test]
fn validate_reality_with_key_ok() {
    let mut p = vmess_profile();
    p.stream = Some(StreamSettings {
        security: "reality".into(),
        reality_public_key: "pbk".into(),
        ..Default::default()
    });
    assert!(validate_ent(&p).is_ok());
}

#[test]
fn validate_xhttp_unsupported() {
    let mut p = vmess_profile();
    p.stream = Some(StreamSettings {
        network: "xhttp".into(),
        ..Default::default()
    });
    assert!(validate_ent(&p).is_err());
    assert_eq!(unsupported_reason(&p), "xhttp_unsupported");
}

#[test]
fn validate_custom_outbound_skips_address() {
    let p = Profile {
        r#type: ProfileType::CustomOutbound,
        address: String::new(),
        port: 0,
        ..Default::default()
    };
    assert!(validate_ent(&p).is_ok());
}

#[test]
fn internal_full_unconfirmed_rejected() {
    let p = Profile {
        r#type: ProfileType::CustomConfig,
        custom_fields_confirmed: false,
        detail: Some(Detail::Custom(CustomDetail {
            core: "internal-full".into(),
            full_config_json: "{}".into(),
            ..Default::default()
        })),
        ..Default::default()
    };
    let err = build(BuildRequest {
        profile: &p,
        group: None,
        settings: None,
        lookup: None,
        preset: None,
        for_test: false,
        for_export: false,
    });
    assert!(err.is_err());
}

#[test]
fn empty_chain_rejected() {
    let p = Profile {
        r#type: ProfileType::Chain,
        detail: Some(Detail::Chain(lavray_model::ChainDetail {
            profile_ids: vec![],
        })),
        ..Default::default()
    };
    let lookup = |_id| unreachable!();
    let err = build(BuildRequest {
        profile: &p,
        group: None,
        settings: None,
        lookup: Some(&lookup),
        preset: None,
        for_test: false,
        for_export: false,
    });
    assert!(err.is_err());
}
