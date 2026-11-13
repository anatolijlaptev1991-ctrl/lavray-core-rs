// SPDX-License-Identifier: GPL-3.0-only

//! V2rayStreamSettings → transport/tls/packet_encoding (порт Go
//! `cfgbuild/outbounds.go` applyStreamSettings/buildTransport/buildTLS).

use crate::settings::BuildSettings;
use crate::util::{obj, split_csv, Obj};
use lavray_model::StreamSettings;
use serde_json::{json, Value};

/// Что из stream-настроек поддерживает тип outbound'а.
#[derive(Default, Clone, Copy)]
pub struct StreamCaps {
    pub transport: bool,
    pub tls: bool,
    pub packet_encoding: bool,
}

/// Применить stream-настройки к outbound (порт applyStreamSettings).
pub fn apply_stream_settings(
    out: &mut Obj,
    s: Option<&StreamSettings>,
    st: &BuildSettings,
    caps: StreamCaps,
) {
    let Some(s) = s else { return };
    let mut transport_type = String::new();
    if caps.transport {
        if let Some(tr) = build_transport(s) {
            transport_type = tr
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            out.insert("transport".into(), Value::Object(tr));
        }
    }
    // L10: непустой RealityPublicKey сам включает reality (иначе plaintext).
    if caps.tls {
        let reality_requested = s.security == "reality" || !s.reality_public_key.is_empty();
        if s.security == "tls" || reality_requested {
            let tls = build_tls(s, st, &transport_type);
            if !tls.is_empty() {
                out.insert("tls".into(), Value::Object(tls));
            }
        }
    }
    if caps.packet_encoding && !s.packet_encoding.is_empty() {
        out.insert("packet_encoding".into(), json!(s.packet_encoding));
    }
}

/// Порт buildTransport (network != tcp + ветка tcp header http).
fn build_transport(s: &StreamSettings) -> Option<Obj> {
    if s.network.is_empty() || s.network == "tcp" {
        if s.header_type == "http" {
            let mut tr = obj();
            tr.insert("type".into(), json!("http"));
            tr.insert("method".into(), json!("GET"));
            tr.insert("path".into(), json!(s.path));
            tr.insert("headers".into(), json!({ "Host": split_csv(&s.host) }));
            return Some(tr);
        }
        return None;
    }
    let mut tr = obj();
    tr.insert("type".into(), json!(s.network));
    match s.network.as_str() {
        "ws" => {
            if !s.host.is_empty() {
                tr.insert("headers".into(), json!({ "Host": s.host }));
            }
            let (path_no_ed, ed_max) = split_ws_early_data(&s.path);
            if !path_no_ed.is_empty() {
                tr.insert("path".into(), json!(path_no_ed));
            }
            if ed_max > 0 {
                tr.insert("max_early_data".into(), json!(ed_max));
                tr.insert(
                    "early_data_header_name".into(),
                    json!("Sec-WebSocket-Protocol"),
                );
            }
            if s.ws_early_data_max > 0 {
                tr.insert("max_early_data".into(), json!(s.ws_early_data_max));
                if !s.ws_early_data_header.is_empty() {
                    tr.insert(
                        "early_data_header_name".into(),
                        json!(s.ws_early_data_header),
                    );
                }
            }
        }
        "http" => {
            if !s.path.is_empty() {
                tr.insert("path".into(), json!(s.path));
            }
            if !s.host.is_empty() {
                tr.insert("host".into(), json!(split_csv(&s.host)));
            }
        }
        "grpc" => {
            if !s.path.is_empty() {
                tr.insert("service_name".into(), json!(s.path));
            }
        }
        "httpupgrade" => {
            if !s.path.is_empty() {
                tr.insert("path".into(), json!(s.path));
            }
            if !s.host.is_empty() {
                tr.insert("host".into(), json!(s.host));
            }
        }
        _ => {} // quic: только type
    }
    Some(tr)
}

/// «/path?ed=2048» → (путь до ?ed=, max_early_data из суффикса).
fn split_ws_early_data(path: &str) -> (String, i64) {
    if let Some(i) = path.find("?ed=") {
        let ed = path[i + 4..].parse::<i64>().unwrap_or(0);
        (path[..i].to_string(), if ed > 0 { ed } else { 0 })
    } else {
        (path.to_string(), 0)
    }
}

/// Порт buildTLS (security == tls | reality).
fn build_tls(s: &StreamSettings, st: &BuildSettings, transport_type: &str) -> Obj {
    let mut tls = obj();
    tls.insert("enabled".into(), json!(true));
    if s.allow_insecure || st.allow_insecure_default {
        tls.insert("insecure".into(), json!(true));
    }
    let sni = s.sni.trim();
    if !sni.is_empty() {
        tls.insert("server_name".into(), json!(sni));
    }
    let cert = s.certificate.trim();
    if !cert.is_empty() {
        tls.insert("certificate".into(), json!(cert));
    }
    let pbk = s.reality_public_key.trim();
    let reality = !pbk.is_empty();
    let alpn = alpn_for_transport(transport_type, split_csv(s.alpn.trim()), reality);
    if !alpn.is_empty() {
        tls.insert("alpn".into(), Value::Array(alpn));
    }
    let mut fp = s.utls_fingerprint.clone();
    if reality {
        let mut r = obj();
        r.insert("enabled".into(), json!(true));
        r.insert("public_key".into(), json!(pbk));
        let sid = s.reality_short_id.trim();
        if !sid.is_empty() {
            let first = sid.split(',').next().unwrap_or("");
            r.insert("short_id".into(), json!(first));
        }
        tls.insert("reality".into(), Value::Object(r));
        if fp.is_empty() {
            fp = "random".into();
        }
    }
    if !fp.is_empty() {
        tls.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
    }
    tls
}

/// ALPN под транспорт (порт alpnForTransport, 0.2.1).
fn alpn_for_transport(transport_type: &str, list: Vec<Value>, reality: bool) -> Vec<Value> {
    if reality || list.is_empty() {
        return list;
    }
    match transport_type {
        "ws" | "httpupgrade" => list
            .into_iter()
            .filter(|p| p != "h2" && p != "h3")
            .collect(),
        "grpc" | "http" => {
            if list.iter().any(|p| p == "h2") {
                list
            } else {
                vec![json!("h2")]
            }
        }
        _ => list,
    }
}
