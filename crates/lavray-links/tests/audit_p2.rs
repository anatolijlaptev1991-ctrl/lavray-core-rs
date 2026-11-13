// SPDX-License-Identifier: GPL-3.0-only

//! Регрессионные тесты аудита links, часть P2: методы ss, flow vless, aid vmess,
//! proto socks/http, query «+», поля hy2/tuic. P1 — в audit_regressions.rs.

use base64::Engine;
use lavray_links::parse_link;
use lavray_model::Detail;

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

// ---- P2-1: методы ss ----

#[test]
fn ss_ctr_methods_accepted() {
    for m in [
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-192-cfb",
        "rc4-md5",
        "chacha20-ietf",
        "xchacha20",
    ] {
        let userinfo = b64(&format!("{m}:pass"));
        assert!(
            parse_link(&format!("ss://{userinfo}@h.com:8388")).is_ok(),
            "метод {m}"
        );
    }
}

#[test]
fn ss_plain_rejected() {
    let userinfo = b64("plain:pass");
    assert!(parse_link(&format!("ss://{userinfo}@h.com:8388")).is_err());
}

// ---- P2-4: vless flow ----

#[test]
fn vless_bad_flow_rejected() {
    assert!(parse_link("vless://uuid@h.com:443?flow=xtls-rprx-direct").is_err());
}

#[test]
fn vless_vision_flow_ok() {
    let p = parse_link("vless://uuid@h.com:443?flow=xtls-rprx-vision").unwrap();
    if let Some(Detail::TrojanVless(d)) = p.detail {
        assert_eq!(d.flow, "xtls-rprx-vision");
    }
}

// ---- P2-5: vmess aid ----

#[test]
fn vmess_aid_overflow_rejected() {
    let json = r#"{"add":"h.com","port":443,"id":"u","aid":"99999"}"#;
    assert!(parse_link(&format!("vmess://{}", b64(json))).is_err());
}

// ---- P2-6: socks4a proto + base64 login ----

#[test]
fn socks4a_proto_socks4() {
    let p = parse_link("socks4a://h.com:1080#S").unwrap();
    if let Some(Detail::SocksHttp(d)) = p.detail {
        assert_eq!(d.proto, "socks4");
    }
}

#[test]
fn socks_base64_login_decoded() {
    let login = b64("user:pass");
    let p = parse_link(&format!("socks://{login}@h.com:1080")).unwrap();
    if let Some(Detail::SocksHttp(d)) = p.detail {
        assert_eq!(d.username, "user");
        assert_eq!(d.password, "pass");
    }
}

// ---- P2-9: query «+» сохраняется ----

#[test]
fn query_plus_preserved() {
    let p = parse_link("vless://uuid@h.com:443?type=ws&path=/a+b#V").unwrap();
    assert_eq!(p.stream.unwrap().path, "/a+b");
}

// ---- P2-2/P2-3: hy2/tuic поля ----

#[test]
fn hy2_mport_and_obfs() {
    let p = parse_link(
        "hy2://pw@h.com:443?mport=1000-2000&obfs=salamander&obfs-password=op&insecure=1",
    )
    .unwrap();
    if let Some(Detail::Hysteria2(d)) = p.detail {
        assert_eq!(d.server_ports, "1000-2000");
        assert_eq!(d.obfs_password, "op");
        assert!(d.allow_insecure);
    }
}

#[test]
fn hy2_bad_mport_rejected() {
    assert!(parse_link("hy2://pw@h.com:443?mport=abc").is_err());
}

#[test]
fn tuic_missing_password_rejected() {
    assert!(parse_link("tuic://uuid@h.com:443").is_err());
}

#[test]
fn tuic_heartbeat_and_zero_rtt() {
    let p = parse_link("tuic://uuid:pw@h.com:443?heartbeat=10s&zero_rtt_handshake=1").unwrap();
    if let Some(Detail::Tuic(d)) = p.detail {
        assert_eq!(d.heartbeat, "10s");
        assert!(d.zero_rtt_handshake);
    }
}

#[test]
fn tuic_bad_congestion_rejected() {
    assert!(parse_link("tuic://uuid:pw@h.com:443?congestion_control=reno").is_err());
}
