// SPDX-License-Identifier: GPL-3.0-only

//! QUICBean (hysteria2/tuic) + CustomBean internal (порт Go
//! `cfgbuild/outbounds.go`). Имена полей sing-box 1.14 (LNB-35/FR-UI-268).

use crate::error::{Error, Result};
use crate::filekeys::reject_file_keys;
use crate::hy2ports::hysteria2_server_ports;
use crate::util::{obj, split_csv, Obj};
use lavray_model::{Detail, Profile};
use serde_json::{json, Value};

/// Общий TLS-блок QUICBean (hysteria2/tuic).
fn quic_tls(
    disable_sni: bool,
    allow_insecure: bool,
    ca: &str,
    sni: &str,
    alpn: &str,
    hysteria2: bool,
) -> Obj {
    let mut tls = obj();
    tls.insert("enabled".into(), json!(true));
    tls.insert("disable_sni".into(), json!(disable_sni));
    tls.insert("insecure".into(), json!(allow_insecure));
    let ca = ca.trim();
    if !ca.is_empty() {
        tls.insert("certificate".into(), json!(ca));
    }
    if !sni.is_empty() {
        tls.insert("server_name".into(), json!(sni));
    }
    if hysteria2 {
        tls.insert("alpn".into(), json!("h3")); // оракул безусловно h3
    } else if !alpn.trim().is_empty() {
        tls.insert("alpn".into(), Value::Array(split_csv(alpn)));
    }
    tls
}

fn base_out(kind: &str, p: &Profile) -> Obj {
    let mut out = obj();
    out.insert("type".into(), json!(kind));
    out.insert("server".into(), json!(p.address));
    out.insert("server_port".into(), json!(p.port));
    out
}

/// Порт buildHysteria2.
pub fn build_hysteria2(p: &Profile) -> Result<Obj> {
    let Some(Detail::Hysteria2(d)) = &p.detail else {
        return Err(Error::invalid(
            "detail",
            "hysteria2: missing or wrong detail type",
        ));
    };
    let mut out = base_out("hysteria2", p);
    out.insert(
        "tls".into(),
        Value::Object(quic_tls(
            d.disable_sni,
            d.allow_insecure,
            &d.ca,
            &d.sni,
            &d.alpn,
            true,
        )),
    );
    if !d.password.is_empty() {
        out.insert("password".into(), json!(d.password));
    }
    if d.upload_mbps > 0 {
        out.insert("up_mbps".into(), json!(d.upload_mbps));
    }
    if d.download_mbps > 0 {
        out.insert("down_mbps".into(), json!(d.download_mbps));
    }
    let ports = hysteria2_server_ports(&d.server_ports)?;
    if !ports.is_empty() {
        out.insert("server_ports".into(), json!(ports));
        let hi = d.hop_interval.trim();
        if !hi.is_empty() {
            out.insert("hop_interval".into(), json!(hi));
        }
    }
    if !d.obfs_password.is_empty() {
        out.insert(
            "obfs".into(),
            json!({ "type": "salamander", "password": d.obfs_password }),
        );
    }
    Ok(out)
}

/// Порт buildTUIC.
pub fn build_tuic(p: &Profile) -> Result<Obj> {
    let Some(Detail::Tuic(d)) = &p.detail else {
        return Err(Error::invalid(
            "detail",
            "tuic: missing or wrong detail type",
        ));
    };
    let mut out = base_out("tuic", p);
    out.insert(
        "tls".into(),
        Value::Object(quic_tls(
            d.disable_sni,
            d.allow_insecure,
            &d.ca,
            &d.sni,
            &d.alpn,
            false,
        )),
    );
    if !d.uuid.is_empty() {
        out.insert("uuid".into(), json!(d.uuid));
    }
    if !d.password.is_empty() {
        out.insert("password".into(), json!(d.password));
    }
    if !d.congestion_control.is_empty() {
        out.insert("congestion_control".into(), json!(d.congestion_control));
    }
    if d.udp_over_stream {
        out.insert("udp_over_stream".into(), json!(true));
    } else if !d.udp_relay_mode.is_empty() {
        out.insert("udp_relay_mode".into(), json!(d.udp_relay_mode));
    }
    if d.zero_rtt_handshake {
        out.insert("zero_rtt_handshake".into(), json!(true));
    }
    let hb = d.heartbeat.trim();
    if !hb.is_empty() {
        out.insert("heartbeat".into(), json!(hb));
    }
    Ok(out)
}

/// Порт buildCustomInternal (core=internal): outbound JSON «как есть» + запрет путей.
pub fn build_custom_internal(p: &Profile) -> Result<Obj> {
    let Some(Detail::Custom(d)) = &p.detail else {
        return Err(Error::invalid(
            "detail",
            "custom: missing or wrong detail type",
        ));
    };
    let raw = d.outbound_json.trim();
    if raw.is_empty() {
        return Err(Error::invalid(
            "custom",
            "custom internal profile: outbound JSON is empty",
        ));
    }
    let out: Obj = serde_json::from_str(raw).map_err(|e| {
        Error::invalid(
            "custom",
            format!("custom internal profile: outbound JSON: {e}"),
        )
    })?;
    reject_file_keys("custom", &Value::Object(out.clone()))?;
    Ok(out)
}
