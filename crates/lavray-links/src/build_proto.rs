// SPDX-License-Identifier: GPL-3.0-only

//! BuildLink для socks/http/ss/trojan/vless + appendStreamQuery (порт Go
//! `links/build.go`). Вынесено из build.rs ради трещотки размеров.

use crate::build::LinkBuilder;
use crate::caps::{SS_METHODS, VLESS_FLOWS};
use crate::util::{check_field_len, encode_b64_url, LinkError, Result, MAX_PLUGIN_LENGTH};
use lavray_model::{Detail, Profile, ProfileType, StreamSettings};

pub(crate) fn build_socks_http(p: &Profile) -> Result<String> {
    let Some(Detail::SocksHttp(d)) = &p.detail else {
        return Err(LinkError(
            "деталь не соответствует профилю socks/http".into(),
        ));
    };
    let mut scheme = "socks5";
    if p.r#type == ProfileType::Http {
        scheme = "http";
        if p.stream.as_ref().is_some_and(|s| s.security == "tls") {
            scheme = "https";
        }
    } else if d.proto == "socks4" {
        scheme = "socks4";
    }
    let mut b = LinkBuilder::new(scheme, p);
    if !d.password.is_empty() {
        b.set_user_pass(&d.username, &d.password);
    } else if !d.username.is_empty() {
        b.set_user(&d.username);
    }
    if let Some(st) = &p.stream {
        if scheme != "https" && st.security == "tls" {
            b.add_q("security", "tls");
        }
        if !st.sni.is_empty() {
            b.add_q("sni", &st.sni);
        }
    }
    Ok(b.build())
}

pub(crate) fn build_ss(p: &Profile) -> Result<String> {
    let Some(Detail::Shadowsocks(d)) = &p.detail else {
        return Err(LinkError(
            "деталь не соответствует профилю shadowsocks".into(),
        ));
    };
    if !SS_METHODS.contains(&d.method.as_str()) {
        return Err(LinkError(format!(
            "ss: метод шифрования {:?} не поддерживается",
            d.method
        )));
    }
    if d.password.is_empty() {
        return Err(LinkError("ss: не указан пароль".into()));
    }
    let mut b = LinkBuilder::new("ss", p);
    if d.method.starts_with("2022-") {
        b.set_user_pass(&d.method, &d.password);
    } else {
        b.set_user(&encode_b64_url(&format!("{}:{}", d.method, d.password)));
    }
    if !d.plugin.is_empty() {
        check_field_len("plugin", &d.plugin, MAX_PLUGIN_LENGTH)?;
        b.add_q("plugin", &d.plugin);
    }
    Ok(b.build())
}

pub(crate) fn build_trojan_vless(p: &Profile) -> Result<String> {
    let Some(Detail::TrojanVless(d)) = &p.detail else {
        return Err(LinkError(
            "деталь не соответствует профилю trojan/vless".into(),
        ));
    };
    if d.password.is_empty() {
        return Err(LinkError(if p.r#type == ProfileType::Vless {
            "vless: не указан UUID".into()
        } else {
            "trojan: не указан пароль".into()
        }));
    }
    if p.r#type == ProfileType::Vless
        && !d.flow.is_empty()
        && !VLESS_FLOWS.contains(&d.flow.as_str())
    {
        return Err(LinkError(format!(
            "vless: flow {:?} не поддерживается",
            d.flow
        )));
    }
    let scheme = if p.r#type == ProfileType::Trojan {
        "trojan"
    } else {
        "vless"
    };
    let mut b = LinkBuilder::new(scheme, p);
    b.set_user(&d.password);
    let default_stream = StreamSettings::default();
    let st = p.stream.as_ref().unwrap_or(&default_stream);
    append_stream_query(&mut b, st, p.r#type == ProfileType::Vless);
    if p.r#type == ProfileType::Vless && !d.flow.is_empty() {
        b.add_q("flow", &d.flow);
    }
    Ok(b.build())
}

/// Параметры транспорта/безопасности для vless/trojan/vmess-URL. security
/// печатается всегда (присутствующий-пустой отличается парсером от отсутствующего).
pub(crate) fn append_stream_query(
    b: &mut LinkBuilder,
    st: &StreamSettings,
    with_encryption_none: bool,
) {
    let mut sec = st.security.clone();
    if sec == "tls" && !st.reality_public_key.is_empty() {
        sec = "reality".into();
    }
    b.add_q("security", &sec);
    b.add_if("sni", &st.sni);
    b.add_if("alpn", &st.alpn);
    if st.allow_insecure {
        b.add_q("allowInsecure", "1");
    }
    b.add_if("fp", &st.utls_fingerprint);
    if sec == "reality" {
        b.add_q("pbk", &st.reality_public_key);
        b.add_if("sid", &st.reality_short_id);
        b.add_if("spx", &st.reality_spx);
    }
    let netw = if st.network.is_empty() {
        "tcp"
    } else {
        &st.network
    };
    b.add_q("type", netw);
    match netw {
        "ws" | "http" | "httpupgrade" | "xhttp" => {
            b.add_if("path", &st.path).add_if("host", &st.host);
            if netw == "xhttp" {
                b.add_if("mode", &st.xhttp_mode)
                    .add_if("extra", &st.xhttp_extra);
            }
        }
        "grpc" => {
            if !st.path.is_empty() {
                b.add_q("serviceName", &st.path);
            }
        }
        "tcp" if st.header_type == "http" => {
            b.add_q("headerType", "http");
            b.add_if("host", &st.host);
            b.add_if("path", &st.path);
        }
        _ => {}
    }
    if with_encryption_none {
        b.add_q("encryption", "none");
    }
}
