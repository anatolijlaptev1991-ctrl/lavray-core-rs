// SPDX-License-Identifier: GPL-3.0-only

//! BuildLink для vmess (v2rayN/URL), hysteria2, tuic (порт Go `links/build.go`).
//! Вынесено из build.rs ради трещотки размеров.

use crate::build::LinkBuilder;
use crate::build_proto::append_stream_query;
use crate::caps::{
    validate_duration, validate_server_ports, TUIC_CONGESTIONS, TUIC_RELAY_MODES, VMESS_SECURITIES,
};
use crate::util::{LinkError, Result};
use base64::Engine;
use lavray_model::{Detail, Profile, StreamSettings};
use serde_json::json;

fn vmess_security(p: &Profile) -> Result<(&lavray_model::VMessDetail, String)> {
    let Some(Detail::VMess(d)) = &p.detail else {
        return Err(LinkError("деталь не соответствует профилю vmess".into()));
    };
    if d.uuid.is_empty() {
        return Err(LinkError("vmess: не указан UUID".into()));
    }
    let scy = if d.security.is_empty() {
        "auto".to_string()
    } else {
        d.security.clone()
    };
    if !VMESS_SECURITIES.contains(&scy.as_str()) {
        return Err(LinkError(format!(
            "vmess: шифрование {scy:?} не поддерживается"
        )));
    }
    Ok((d, scy))
}

/// Формат v2rayN: vmess://BASE64(JSON) (FR-UI-164).
pub(crate) fn build_vmess_v2rayn(p: &Profile) -> Result<String> {
    let (d, scy) = vmess_security(p)?;
    let default_stream = StreamSettings::default();
    let st = p.stream.as_ref().unwrap_or(&default_stream);
    let netw = if st.network.is_empty() {
        "tcp"
    } else {
        &st.network
    };
    let tls = if st.security == "tls" || st.security == "reality" {
        "tls"
    } else {
        ""
    };
    let mut obj = json!({
        "v": "2", "ps": p.name, "add": p.address, "port": p.port,
        "id": d.uuid, "aid": d.alter_id, "net": netw, "host": st.host,
        "path": st.path, "type": st.header_type, "scy": scy, "tls": tls, "sni": st.sni,
    });
    let map = obj.as_object_mut().unwrap();
    if !st.alpn.is_empty() {
        map.insert("alpn".into(), json!(st.alpn));
    }
    if !st.utls_fingerprint.is_empty() {
        map.insert("fp".into(), json!(st.utls_fingerprint));
    }
    if !st.reality_public_key.is_empty() {
        map.insert("pbk".into(), json!(st.reality_public_key));
        if !st.reality_short_id.is_empty() {
            map.insert("sid".into(), json!(st.reality_short_id));
        }
        if !st.reality_spx.is_empty() {
            map.insert("spx".into(), json!(st.reality_spx));
        }
    }
    let j = serde_json::to_vec(&obj).map_err(|e| LinkError(e.to_string()))?;
    Ok(format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(j)
    ))
}

/// URL-формат vmess (XTLS #716).
pub(crate) fn build_vmess_url(p: &Profile) -> Result<String> {
    let (d, scy) = vmess_security(p)?;
    let mut b = LinkBuilder::new("vmess", p);
    b.set_user(&d.uuid);
    let default_stream = StreamSettings::default();
    let st = p.stream.as_ref().unwrap_or(&default_stream);
    b.add_q("encryption", &scy);
    append_stream_query(&mut b, st, false);
    Ok(b.build())
}

pub(crate) fn build_hysteria2(p: &Profile) -> Result<String> {
    let Some(Detail::Hysteria2(d)) = &p.detail else {
        return Err(LinkError(
            "деталь не соответствует профилю hysteria2".into(),
        ));
    };
    if d.password.is_empty() {
        return Err(LinkError("hy2: не указан пароль".into()));
    }
    validate_server_ports(&d.server_ports)?;
    if !d.hop_interval.is_empty() {
        validate_duration("hop_interval", &d.hop_interval)?;
    }
    let mut b = LinkBuilder::new("hy2", p);
    if let Some((u, pass)) = d.password.split_once(':') {
        b.set_user_pass(u, pass);
    } else {
        b.set_user(&d.password);
    }
    if !d.obfs_password.is_empty() {
        b.add_q("obfs", "salamander");
        b.add_q("obfs-password", &d.obfs_password);
    }
    b.add_if("mport", &d.server_ports);
    b.add_if("hop_interval", &d.hop_interval);
    if d.upload_mbps > 0 {
        b.add_q("upmbps", &d.upload_mbps.to_string());
    }
    if d.download_mbps > 0 {
        b.add_q("downmbps", &d.download_mbps.to_string());
    }
    if d.allow_insecure {
        b.add_q("insecure", "1");
    }
    if d.disable_sni {
        b.add_q("disable_sni", "1");
    }
    b.add_if("sni", &d.sni);
    b.add_if("alpn", &d.alpn);
    Ok(b.build())
}

pub(crate) fn build_tuic(p: &Profile) -> Result<String> {
    let Some(Detail::Tuic(d)) = &p.detail else {
        return Err(LinkError("деталь не соответствует профилю tuic".into()));
    };
    if d.uuid.is_empty() {
        return Err(LinkError("tuic: не указан UUID".into()));
    }
    if d.password.is_empty() {
        return Err(LinkError("tuic: не указан пароль".into()));
    }
    if !TUIC_CONGESTIONS.contains(&d.congestion_control.as_str()) {
        return Err(LinkError(format!(
            "tuic: congestion_control {:?} не поддерживается",
            d.congestion_control
        )));
    }
    if !TUIC_RELAY_MODES.contains(&d.udp_relay_mode.as_str()) {
        return Err(LinkError(format!(
            "tuic: udp_relay_mode {:?} не поддерживается",
            d.udp_relay_mode
        )));
    }
    if !d.heartbeat.is_empty() {
        validate_duration("heartbeat", &d.heartbeat)?;
    }
    let mut b = LinkBuilder::new("tuic", p);
    b.set_user_pass(&d.uuid, &d.password);
    b.add_if("congestion_control", &d.congestion_control);
    b.add_if("alpn", &d.alpn);
    b.add_if("sni", &d.sni);
    b.add_if("udp_relay_mode", &d.udp_relay_mode);
    if d.zero_rtt_handshake {
        b.add_q("zero_rtt_handshake", "1");
    }
    b.add_if("heartbeat", &d.heartbeat);
    if d.allow_insecure {
        b.add_q("allow_insecure", "1");
    }
    if d.disable_sni {
        b.add_q("disable_sni", "1");
    }
    Ok(b.build())
}
