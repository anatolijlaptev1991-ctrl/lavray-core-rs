// SPDX-License-Identifier: GPL-3.0-only

//! Профиль модели → sing-box outbound JSON (порт Go `cfgbuild/outbounds.go`,
//! fmt/Bean2CoreObj_box.cpp). Диспетчер по типу + socks/ss/vmess/trojan-vless.

use crate::error::{Error, Result};
use crate::outbounds_quic::{build_custom_internal, build_hysteria2, build_tuic};
use crate::settings::BuildSettings;
use crate::stream::{apply_stream_settings, StreamCaps};
use crate::util::{obj, Obj};
use lavray_model::{Detail, Profile, ProfileType};
use serde_json::json;

/// Построить outbound для одиночного профиля без тега (порт buildOutbound).
pub fn build_outbound(p: &Profile, st: &BuildSettings) -> Result<Obj> {
    match p.r#type {
        ProfileType::Socks | ProfileType::Http => build_socks_http(p, st),
        ProfileType::Shadowsocks => build_shadowsocks(p),
        ProfileType::VMess => build_vmess(p, st),
        ProfileType::Trojan | ProfileType::Vless => build_trojan_vless(p, st),
        ProfileType::Hysteria2 => build_hysteria2(p),
        ProfileType::Tuic => build_tuic(p),
        ProfileType::CustomOutbound => build_custom_internal(p),
        _ => Err(Error::precondition(
            "type",
            format!("unsupported outbound type {:?}", p.r#type),
        )),
    }
}

fn base_out(kind: &str, p: &Profile) -> Obj {
    let mut out = obj();
    out.insert("type".into(), json!(kind));
    out.insert("server".into(), json!(p.address));
    out.insert("server_port".into(), json!(p.port));
    out
}

fn build_socks_http(p: &Profile, st: &BuildSettings) -> Result<Obj> {
    let Some(Detail::SocksHttp(d)) = &p.detail else {
        return Err(Error::invalid(
            "detail",
            "socks/http: missing or wrong detail type",
        ));
    };
    let mut out = base_out("socks", p);
    let mut is_http = false;
    match d.proto.as_str() {
        "http" => {
            out.insert("type".into(), json!("http"));
            is_http = true;
        }
        "socks4" => {
            out.insert("version".into(), json!("4"));
        }
        _ => {}
    }
    if !d.username.is_empty() && !d.password.is_empty() {
        out.insert("username".into(), json!(d.username));
        out.insert("password".into(), json!(d.password));
    }
    if is_http {
        apply_stream_settings(
            &mut out,
            p.stream.as_ref(),
            st,
            StreamCaps {
                tls: true,
                ..Default::default()
            },
        );
    }
    Ok(out)
}

fn build_shadowsocks(p: &Profile) -> Result<Obj> {
    let Some(Detail::Shadowsocks(d)) = &p.detail else {
        return Err(Error::invalid(
            "detail",
            "shadowsocks: missing or wrong detail type",
        ));
    };
    if d.method.is_empty() || d.password.is_empty() {
        return Err(Error::invalid(
            "method",
            "shadowsocks: method and password are required",
        ));
    }
    let mut out = base_out("shadowsocks", p);
    out.insert("method".into(), json!(d.method));
    out.insert("password".into(), json!(d.password));
    if d.udp_over_tcp != 0 {
        out.insert(
            "udp_over_tcp".into(),
            json!({ "enabled": true, "version": d.udp_over_tcp }),
        );
    } else {
        out.insert("udp_over_tcp".into(), json!(false));
    }
    let plugin = d.plugin.trim();
    if !plugin.is_empty() {
        let (name, opts) = match plugin.split_once(';') {
            Some((n, o)) => (n, o),
            None => (plugin, ""),
        };
        out.insert("plugin".into(), json!(name));
        if !opts.is_empty() {
            out.insert("plugin_opts".into(), json!(opts));
        }
    }
    Ok(out)
}

fn build_vmess(p: &Profile, st: &BuildSettings) -> Result<Obj> {
    let Some(Detail::VMess(d)) = &p.detail else {
        return Err(Error::invalid(
            "detail",
            "vmess: missing or wrong detail type",
        ));
    };
    let uuid = d.uuid.trim();
    if uuid.is_empty() {
        return Err(Error::invalid("uuid", "vmess: uuid is required"));
    }
    let mut out = base_out("vmess", p);
    out.insert("uuid".into(), json!(uuid));
    out.insert("alter_id".into(), json!(d.alter_id)); // оракул эмитит всегда
    if !d.security.is_empty() {
        out.insert("security".into(), json!(d.security));
    }
    apply_stream_settings(
        &mut out,
        p.stream.as_ref(),
        st,
        StreamCaps {
            transport: true,
            tls: true,
            packet_encoding: true,
        },
    );
    Ok(out)
}

fn build_trojan_vless(p: &Profile, st: &BuildSettings) -> Result<Obj> {
    let Some(Detail::TrojanVless(d)) = &p.detail else {
        return Err(Error::invalid(
            "detail",
            "trojan/vless: missing or wrong detail type",
        ));
    };
    let vless = p.r#type == ProfileType::Vless;
    let mut out = base_out(if vless { "vless" } else { "trojan" }, p);
    if vless {
        let uuid = d.password.trim();
        if uuid.is_empty() {
            return Err(Error::invalid("uuid", "vless: uuid is required"));
        }
        out.insert("uuid".into(), json!(uuid));
        let mut flow = d
            .flow
            .strip_suffix("-udp443")
            .unwrap_or(&d.flow)
            .to_string();
        if flow == "none" {
            flow = String::new();
        }
        if !flow.is_empty() {
            out.insert("flow".into(), json!(flow));
        }
    } else {
        if d.password.is_empty() {
            return Err(Error::invalid("password", "trojan: password is required"));
        }
        out.insert("password".into(), json!(d.password));
    }
    apply_stream_settings(
        &mut out,
        p.stream.as_ref(),
        st,
        StreamCaps {
            transport: true,
            tls: true,
            packet_encoding: vless,
        },
    );
    Ok(out)
}
