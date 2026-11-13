// SPDX-License-Identifier: GPL-3.0-only

//! Тесты волны 3: nekoray:// импорт (FR-UI-191, P2-10) и serverDescription
//! (0.2.1, P2-11). Паритет Go links/neko.go, description.go.

use base64::Engine;
use lavray_links::parse_link;
use lavray_model::{Detail, ProfileType};

fn b64url(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE.encode(s)
}

fn b64std(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

// ---- nekoray ----

#[test]
fn nekoray_vmess_import() {
    let bean = r#"{"name":"N","addr":"h.com","port":443,"id":"uuid-1","aid":0,"sec":"auto"}"#;
    let p = parse_link(&format!("nekoray://vmess#{}", b64url(bean))).unwrap();
    assert_eq!(p.r#type, ProfileType::VMess);
    assert_eq!(p.address, "h.com");
    assert_eq!(p.port, 443);
    if let Some(Detail::VMess(d)) = p.detail {
        assert_eq!(d.uuid, "uuid-1");
    } else {
        panic!("VMess detail");
    }
}

#[test]
fn nekoray_socks_http_type() {
    let bean = r#"{"name":"H","addr":"h.com","port":8080,"v":-80,"username":"u","password":"p"}"#;
    let p = parse_link(&format!("nekoray://http#{}", b64url(bean))).unwrap();
    assert_eq!(p.r#type, ProfileType::Http);
    if let Some(Detail::SocksHttp(d)) = p.detail {
        assert_eq!(d.proto, "http");
        assert_eq!(d.username, "u");
    }
}

#[test]
fn nekoray_drops_custom_config() {
    // LNB-25/FR-UI-257: c_cfg/c_out из ссылки отбрасываются.
    let bean =
        r#"{"name":"C","addr":"h.com","port":443,"id":"u","c_cfg":"{\"evil\":1}","c_out":"x"}"#;
    let p = parse_link(&format!("nekoray://vmess#{}", b64url(bean))).unwrap();
    assert!(p.custom_config_json.is_empty());
    assert!(p.custom_outbound_json.is_empty());
}

#[test]
fn nekoray_stream_imported() {
    let bean = r#"{"name":"V","addr":"h.com","port":443,"id":"u","stream":{"net":"ws","sec":"tls","sni":"h.com","path":"/p"}}"#;
    let p = parse_link(&format!("nekoray://vmess#{}", b64url(bean))).unwrap();
    let st = p.stream.expect("stream");
    assert_eq!(st.network, "ws");
    assert_eq!(st.security, "tls");
    assert_eq!(st.sni, "h.com");
}

#[test]
fn nekoray_reality_canonicalized() {
    let bean =
        r#"{"name":"V","addr":"h.com","port":443,"pass":"u","stream":{"net":"tcp","pbk":"KEY"}}"#;
    let p = parse_link(&format!("nekoray://vless#{}", b64url(bean))).unwrap();
    assert_eq!(p.stream.unwrap().security, "reality");
}

#[test]
fn nekoray_chain_import() {
    let bean = r#"{"name":"Ch","list":[1,2,3]}"#;
    let p = parse_link(&format!("nekoray://chain#{}", b64url(bean))).unwrap();
    assert_eq!(p.r#type, ProfileType::Chain);
    if let Some(Detail::Chain(d)) = p.detail {
        assert_eq!(d.profile_ids, vec![1, 2, 3]);
    }
}

#[test]
fn nekoray_bad_format_rejected() {
    assert!(parse_link("nekoray://vmess").is_err());
    assert!(parse_link("nekoray://#abc").is_err());
    assert!(parse_link("nekoray://vmess#!!!").is_err());
}

#[test]
fn nekoray_ss_bad_method_rejected() {
    let bean = r#"{"name":"S","addr":"h.com","port":8388,"method":"rot13","pass":"p"}"#;
    assert!(parse_link(&format!("nekoray://shadowsocks#{}", b64url(bean))).is_err());
}

// ---- serverDescription ----

#[test]
fn server_description_stripped_to_notes() {
    let desc = b64std("Описание сервера");
    let link = format!("trojan://pw@h.com:443#Имя?serverDescription={desc}");
    let p = parse_link(&link).unwrap();
    assert_eq!(p.name, "Имя");
    assert_eq!(p.notes, "Описание сервера");
}

#[test]
fn server_description_encoded_marker() {
    let desc = b64std("Текст");
    let link = format!("trojan://pw@h.com:443#Name%3FserverDescription%3D{desc}");
    let p = parse_link(&link).unwrap();
    assert_eq!(p.name, "Name");
    assert_eq!(p.notes, "Текст");
}

#[test]
fn server_description_bad_base64_just_stripped() {
    let link = "trojan://pw@h.com:443#Name?serverDescription=!!!notbase64";
    let p = parse_link(link).unwrap();
    assert_eq!(p.name, "Name");
    assert!(p.notes.is_empty());
}

#[test]
fn no_description_unchanged() {
    let p = parse_link("trojan://pw@h.com:443#PlainName").unwrap();
    assert_eq!(p.name, "PlainName");
    assert!(p.notes.is_empty());
}

#[test]
fn description_query_suffix_truncated() {
    // decodeDescription обрезает значение по «&» (хвост query-параметров).
    let desc = b64std("Описание");
    let link = format!("trojan://pw@h.com:443#Name?serverDescription={desc}&other=1");
    let p = parse_link(&link).unwrap();
    assert_eq!(p.name, "Name");
    assert_eq!(p.notes, "Описание");
}

#[test]
fn description_vmess_json_name_preserved() {
    // vmess v2rayN: имя из JSON ps сохраняется, описания нет → заметки пусты.
    let json = r#"{"add":"h.com","port":"443","id":"u","ps":"MyName"}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(json);
    let p = parse_link(&format!("vmess://{b64}")).unwrap();
    assert_eq!(p.name, "MyName");
    assert!(p.notes.is_empty());
}
