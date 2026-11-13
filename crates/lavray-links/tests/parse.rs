// SPDX-License-Identifier: GPL-3.0-only

//! Тесты парсинга прокси-ссылок: все схемы, форматы, ошибки.

use base64::Engine;
use lavray_links::parse_link;
use lavray_model::{Detail, ProfileType};

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

#[test]
fn empty_link_rejected() {
    assert!(parse_link("").is_err());
    assert!(parse_link("   ").is_err());
}

#[test]
fn no_scheme_rejected() {
    assert!(parse_link("example.com:443").is_err());
    assert!(parse_link("://foo").is_err());
}

#[test]
fn unsupported_scheme_rejected() {
    assert!(parse_link("ftp://example.com").is_err());
}

#[test]
fn happ_is_subscription() {
    let err = parse_link("happ://encrypted").unwrap_err();
    assert!(err.0.contains("подписка"));
}

#[test]
fn vmess_base64_json() {
    let json = r#"{"v":"2","ps":"Test","add":"example.com","port":"443","id":"uuid-1","aid":"0","scy":"auto"}"#;
    let link = format!("vmess://{}", b64(json));
    let p = parse_link(&link).unwrap();
    assert_eq!(p.r#type, ProfileType::VMess);
    assert_eq!(p.address, "example.com");
    assert_eq!(p.port, 443);
    assert_eq!(p.name, "Test");
    if let Some(Detail::VMess(d)) = p.detail {
        assert_eq!(d.uuid, "uuid-1");
        assert_eq!(d.security, "auto");
    } else {
        panic!("ожидался VMess detail");
    }
}

#[test]
fn vmess_port_as_number() {
    let json = r#"{"add":"h","port":8443,"id":"u","scy":"none"}"#;
    let p = parse_link(&format!("vmess://{}", b64(json))).unwrap();
    assert_eq!(p.port, 8443);
}

#[test]
fn vmess_missing_add_rejected() {
    let json = r#"{"port":"443","id":"u"}"#;
    assert!(parse_link(&format!("vmess://{}", b64(json))).is_err());
}

#[test]
fn vmess_bad_security_rejected() {
    let json = r#"{"add":"h","port":"443","id":"u","scy":"rot13"}"#;
    assert!(parse_link(&format!("vmess://{}", b64(json))).is_err());
}

#[test]
fn vmess_url_format() {
    let p = parse_link("vmess://uuid-abc@example.com:443?encryption=auto#Name").unwrap();
    assert_eq!(p.r#type, ProfileType::VMess);
    assert_eq!(p.address, "example.com");
    assert_eq!(p.port, 443);
    assert_eq!(p.name, "Name");
    if let Some(Detail::VMess(d)) = p.detail {
        assert_eq!(d.uuid, "uuid-abc");
    } else {
        panic!("VMess detail");
    }
}

#[test]
fn vmess_url_missing_uuid_rejected() {
    assert!(parse_link("vmess://example.com:443").is_err());
}

#[test]
fn vless_link() {
    let p = parse_link("vless://uuid-1@example.com:443?flow=xtls-rprx-vision#V").unwrap();
    assert_eq!(p.r#type, ProfileType::Vless);
    assert_eq!(p.address, "example.com");
    if let Some(Detail::TrojanVless(d)) = p.detail {
        assert_eq!(d.password, "uuid-1");
        assert_eq!(d.flow, "xtls-rprx-vision");
    } else {
        panic!("TrojanVless detail");
    }
}

#[test]
fn trojan_link() {
    let p = parse_link("trojan://password@example.com:443#T").unwrap();
    assert_eq!(p.r#type, ProfileType::Trojan);
    if let Some(Detail::TrojanVless(d)) = p.detail {
        assert_eq!(d.password, "password");
    } else {
        panic!("TrojanVless detail");
    }
}

#[test]
fn trojan_missing_password_rejected() {
    assert!(parse_link("trojan://example.com:443").is_err());
}

#[test]
fn ss_sip002_base64_userinfo() {
    let userinfo = b64("aes-256-gcm:secretpass");
    let link = format!("ss://{userinfo}@example.com:8388#SS");
    let p = parse_link(&link).unwrap();
    assert_eq!(p.r#type, ProfileType::Shadowsocks);
    assert_eq!(p.address, "example.com");
    assert_eq!(p.port, 8388);
    if let Some(Detail::Shadowsocks(d)) = p.detail {
        assert_eq!(d.method, "aes-256-gcm");
        assert_eq!(d.password, "secretpass");
    } else {
        panic!("Shadowsocks detail");
    }
}

#[test]
fn ss_v2rayn_base64() {
    let inner = b64("aes-256-gcm:pass@example.com:8388");
    let link = format!("ss://{inner}#Name");
    let p = parse_link(&link).unwrap();
    assert_eq!(p.address, "example.com");
    assert_eq!(p.port, 8388);
    assert_eq!(p.name, "Name");
}

#[test]
fn ss_unsupported_method_rejected() {
    let userinfo = b64("rot13:pass");
    assert!(parse_link(&format!("ss://{userinfo}@h:8388")).is_err());
}

#[test]
fn ss_missing_password_rejected() {
    let userinfo = b64("aes-256-gcm:");
    assert!(parse_link(&format!("ss://{userinfo}@h:8388")).is_err());
}

#[test]
fn hysteria2_link() {
    let p = parse_link("hy2://password@example.com:443?sni=example.com&insecure=1#H").unwrap();
    assert_eq!(p.r#type, ProfileType::Hysteria2);
    if let Some(Detail::Hysteria2(d)) = p.detail {
        assert_eq!(d.password, "password");
        assert_eq!(d.sni, "example.com");
        assert!(d.allow_insecure);
    } else {
        panic!("Hysteria2 detail");
    }
}

#[test]
fn tuic_link() {
    let p = parse_link("tuic://uuid-1:pass@example.com:443?congestion_control=bbr#T").unwrap();
    assert_eq!(p.r#type, ProfileType::Tuic);
    if let Some(Detail::Tuic(d)) = p.detail {
        assert_eq!(d.uuid, "uuid-1");
        assert_eq!(d.password, "pass");
        assert_eq!(d.congestion_control, "bbr");
    } else {
        panic!("Tuic detail");
    }
}

#[test]
fn tuic_missing_uuid_rejected() {
    assert!(parse_link("tuic://example.com:443").is_err());
}

#[test]
fn socks5_link() {
    let p = parse_link("socks5://user:pass@example.com:1080#S").unwrap();
    assert_eq!(p.r#type, ProfileType::Socks);
    if let Some(Detail::SocksHttp(d)) = p.detail {
        assert_eq!(d.proto, "socks5");
        assert_eq!(d.username, "user");
        assert_eq!(d.password, "pass");
    } else {
        panic!("SocksHttp detail");
    }
}

#[test]
fn http_link_default_port() {
    let p = parse_link("http://example.com#H").unwrap();
    assert_eq!(p.r#type, ProfileType::Http);
    assert_eq!(p.port, 80);
}

#[test]
fn https_link_default_port() {
    let p = parse_link("https://example.com").unwrap();
    assert_eq!(p.port, 443);
}

#[test]
fn invalid_port_rejected() {
    assert!(parse_link("trojan://pw@example.com:99999").is_err());
}

#[test]
fn scheme_case_insensitive() {
    let p = parse_link("VLESS://uuid@example.com:443").unwrap();
    assert_eq!(p.r#type, ProfileType::Vless);
}
