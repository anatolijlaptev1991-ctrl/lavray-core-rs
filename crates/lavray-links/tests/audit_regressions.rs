// SPDX-License-Identifier: GPL-3.0-only

//! Регрессионные тесты аудита links, часть P1: stream-импорт (P1-1), пароль hy2
//! (P1-2), порт 0 (P1-3). P2 — в audit_p2.rs. Regression-first.

use base64::Engine;
use lavray_links::parse_link;
use lavray_model::{Detail, ProfileType};

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

// ---- P1-1: stream-импорт ----

#[test]
fn vless_ws_reality_stream_imported() {
    let p = parse_link(
        "vless://uuid@h.com:443?type=ws&security=reality&pbk=PBK&sid=SID&sni=example.com&path=/ws&host=example.com#N",
    )
    .unwrap();
    let st = p.stream.expect("stream импортирован");
    assert_eq!(st.network, "ws");
    assert_eq!(st.security, "reality");
    assert_eq!(st.reality_public_key, "PBK");
    assert_eq!(st.reality_short_id, "SID");
    assert_eq!(st.sni, "example.com");
    assert_eq!(st.path, "/ws");
}

#[test]
fn trojan_tls_default_security() {
    let p = parse_link("trojan://pw@h.com:443?sni=example.com#T").unwrap();
    let st = p.stream.expect("trojan tls по умолчанию");
    assert_eq!(st.security, "tls");
    assert_eq!(st.sni, "example.com");
}

#[test]
fn vless_no_security_by_default() {
    let p = parse_link("vless://uuid@h.com:443#V").unwrap();
    // Go applyStreamFromQuery всегда ставит network="tcp"; security пуст (def "").
    let st = p.stream.expect("network=tcp эмитится всегда");
    assert_eq!(st.network, "tcp");
    assert!(st.security.is_empty());
}

#[test]
fn vmess_json_stream_imported() {
    let json = r#"{"add":"h.com","port":"443","id":"u","aid":"0","scy":"auto","net":"ws","host":"h.com","path":"/p","tls":"tls","sni":"h.com"}"#;
    let p = parse_link(&format!("vmess://{}", b64(json))).unwrap();
    let st = p.stream.expect("vmess stream из JSON");
    assert_eq!(st.network, "ws");
    assert_eq!(st.security, "tls");
    assert_eq!(st.path, "/p");
    assert_eq!(st.sni, "h.com");
}

#[test]
fn vmess_json_reality_via_pbk() {
    let json = r#"{"add":"h.com","port":443,"id":"u","net":"tcp","tls":"","pbk":"KEY"}"#;
    let p = parse_link(&format!("vmess://{}", b64(json))).unwrap();
    assert_eq!(p.stream.unwrap().security, "reality");
}

#[test]
fn https_socks_stream_tls() {
    let p = parse_link("https://h.com:443#H").unwrap();
    assert_eq!(p.r#type, ProfileType::Http);
    if let Some(Detail::SocksHttp(d)) = p.detail {
        assert_eq!(d.proto, "http"); // P2-6: не "https"
    } else {
        panic!("SocksHttp detail");
    }
    assert_eq!(p.stream.unwrap().security, "tls");
}

// ---- P1-2: пароль hy2 ----

#[test]
fn hy2_user_pass_joined() {
    let p = parse_link("hy2://user:pass@h.com:443#H").unwrap();
    if let Some(Detail::Hysteria2(d)) = p.detail {
        assert_eq!(d.password, "user:pass");
    } else {
        panic!("Hysteria2 detail");
    }
}

#[test]
fn hy2_user_only() {
    let p = parse_link("hy2://secret@h.com:443#H").unwrap();
    if let Some(Detail::Hysteria2(d)) = p.detail {
        assert_eq!(d.password, "secret");
    } else {
        panic!("Hysteria2 detail");
    }
}

#[test]
fn hy2_empty_password_rejected() {
    assert!(parse_link("hy2://@h.com:443").is_err());
}

// ---- P1-3: порт 0 ----

#[test]
fn vmess_json_port_zero_rejected() {
    let json = r#"{"add":"h.com","port":0,"id":"u"}"#;
    assert!(parse_link(&format!("vmess://{}", b64(json))).is_err());
}

#[test]
fn vmess_json_port_missing_rejected() {
    let json = r#"{"add":"h.com","id":"u"}"#;
    assert!(parse_link(&format!("vmess://{}", b64(json))).is_err());
}

#[test]
fn ss_port_zero_rejected() {
    let userinfo = b64("aes-256-gcm:pass");
    assert!(parse_link(&format!("ss://{userinfo}@h.com:0")).is_err());
}
