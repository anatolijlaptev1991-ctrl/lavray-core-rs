// SPDX-License-Identifier: GPL-3.0-only

//! Round-trip тесты BuildLink (ссылка→профиль→ссылка, FR-UI-190). Паритет Go
//! links/build.go + roundtrip_test.go.

use lavray_links::{build_link, parse_link};
use lavray_model::{Detail, Profile, ProfileType};

fn roundtrip(link: &str) -> Profile {
    let p = parse_link(link).unwrap();
    let rebuilt = build_link(&p).unwrap();
    parse_link(&rebuilt).unwrap()
}

#[test]
fn vmess_v2rayn_roundtrip() {
    let p = roundtrip("vmess://eyJhZGQiOiJoLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6InV1aWQiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsInBzIjoiTiJ9");
    assert_eq!(p.r#type, ProfileType::VMess);
    assert_eq!(p.address, "h.com");
    assert_eq!(p.port, 443);
    if let Some(Detail::VMess(d)) = p.detail {
        assert_eq!(d.uuid, "uuid");
    }
}

#[test]
fn vless_stream_roundtrip() {
    let p = roundtrip("vless://uuid@h.com:443?type=ws&security=tls&sni=h.com&path=/ws#V");
    assert_eq!(p.r#type, ProfileType::Vless);
    let st = p.stream.expect("stream");
    assert_eq!(st.network, "ws");
    assert_eq!(st.security, "tls");
    assert_eq!(st.sni, "h.com");
    assert_eq!(st.path, "/ws");
}

#[test]
fn vless_reality_roundtrip() {
    let p =
        roundtrip("vless://uuid@h.com:443?type=tcp&security=reality&pbk=KEY&sid=SID&sni=h.com#V");
    let st = p.stream.expect("stream");
    assert_eq!(st.security, "reality");
    assert_eq!(st.reality_public_key, "KEY");
    assert_eq!(st.reality_short_id, "SID");
}

#[test]
fn trojan_roundtrip() {
    let p = roundtrip("trojan://pass@h.com:443?security=tls&sni=h.com#T");
    assert_eq!(p.r#type, ProfileType::Trojan);
    if let Some(Detail::TrojanVless(d)) = p.detail {
        assert_eq!(d.password, "pass");
    }
    assert_eq!(p.stream.unwrap().sni, "h.com");
}

fn ss_link(method: &str) -> String {
    let p = Profile {
        r#type: ProfileType::Shadowsocks,
        name: "S".into(),
        address: "h.com".into(),
        port: 8388,
        detail: Some(Detail::Shadowsocks(lavray_model::ShadowsocksDetail {
            method: method.into(),
            password: "pass".into(),
            ..Default::default()
        })),
        ..Default::default()
    };
    build_link(&p).unwrap()
}

#[test]
fn ss_roundtrip() {
    let p = roundtrip(&ss_link("aes-256-gcm"));
    assert_eq!(p.r#type, ProfileType::Shadowsocks);
    if let Some(Detail::Shadowsocks(d)) = p.detail {
        assert_eq!(d.method, "aes-256-gcm");
        assert_eq!(d.password, "pass");
    }
}

#[test]
fn ss_2022_roundtrip() {
    let p = roundtrip(&ss_link("2022-blake3-aes-256-gcm"));
    if let Some(Detail::Shadowsocks(d)) = p.detail {
        assert_eq!(d.method, "2022-blake3-aes-256-gcm");
    }
}

#[test]
fn hy2_roundtrip() {
    let p = roundtrip("hy2://user:pass@h.com:443?insecure=1&sni=h.com#H");
    assert_eq!(p.r#type, ProfileType::Hysteria2);
    if let Some(Detail::Hysteria2(d)) = p.detail {
        assert_eq!(d.password, "user:pass");
        assert!(d.allow_insecure);
        assert_eq!(d.sni, "h.com");
    }
}

#[test]
fn tuic_roundtrip() {
    let p = roundtrip("tuic://uuid:pass@h.com:443?congestion_control=bbr&sni=h.com#T");
    assert_eq!(p.r#type, ProfileType::Tuic);
    if let Some(Detail::Tuic(d)) = p.detail {
        assert_eq!(d.uuid, "uuid");
        assert_eq!(d.password, "pass");
        assert_eq!(d.congestion_control, "bbr");
    }
}

#[test]
fn socks_roundtrip() {
    let p = roundtrip("socks://user:pass@h.com:1080#S");
    assert_eq!(p.r#type, ProfileType::Socks);
    if let Some(Detail::SocksHttp(d)) = p.detail {
        assert_eq!(d.username, "user");
        assert_eq!(d.password, "pass");
    }
}

#[test]
fn name_with_special_chars_roundtrip() {
    let p = parse_link("trojan://pass@h.com:443#Имя%20сервера").unwrap();
    let rebuilt = build_link(&p).unwrap();
    let p2 = parse_link(&rebuilt).unwrap();
    assert_eq!(p2.name, "Имя сервера");
}

#[test]
fn custom_type_not_exported() {
    let p = Profile {
        r#type: ProfileType::CustomOutbound,
        ..Default::default()
    };
    assert!(build_link(&p).is_err());
}

#[test]
fn chain_type_not_exported() {
    let p = Profile {
        r#type: ProfileType::Chain,
        ..Default::default()
    };
    assert!(build_link(&p).is_err());
}

#[test]
fn naive_type_not_exported() {
    let p = Profile {
        r#type: ProfileType::Naive,
        ..Default::default()
    };
    assert!(build_link(&p).is_err());
}

#[test]
fn invalid_port_rejected() {
    let p = Profile {
        r#type: ProfileType::Socks,
        address: "h.com".into(),
        port: 0,
        detail: Some(Detail::SocksHttp(lavray_model::SocksHttpDetail::default())),
        ..Default::default()
    };
    assert!(build_link(&p).is_err());
}
