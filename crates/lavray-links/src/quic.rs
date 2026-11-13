// SPDX-License-Identifier: GPL-3.0-only

//! Парсер hysteria2:// (hy2://) и tuic://. Паритет с Go `links/parse.go`.

use crate::util::{
    apply_default_port, frag_name, host_port, parse_url, query_get, query_pairs, user_info,
    LinkError, Result,
};
use lavray_model::{Detail, Hysteria2Detail, Profile, ProfileType, TuicDetail};

/// Разобрать hysteria2:// / hy2:// ссылку.
pub fn parse_hysteria2(s: &str) -> Result<Profile> {
    let u = parse_url(s)?;
    let (password, _) = user_info(&u);
    let (host, port, present) = host_port(&u)?;
    let port = apply_default_port(port, present, 443)?;
    let pairs = query_pairs(&u);
    let get = |k: &str| query_get(&pairs, k).unwrap_or("").to_string();
    let detail = Hysteria2Detail {
        password,
        obfs_password: get("obfs-password"),
        server_ports: get("server_ports"),
        hop_interval: get("hop_interval"),
        sni: get("sni"),
        alpn: get("alpn"),
        allow_insecure: get("insecure") == "1" || get("allowInsecure") == "1",
        ..Default::default()
    };
    Ok(Profile {
        r#type: ProfileType::Hysteria2,
        name: frag_name(&u),
        address: host,
        port,
        detail: Some(Detail::Hysteria2(detail)),
        ..Default::default()
    })
}

/// Разобрать tuic:// ссылку.
pub fn parse_tuic(s: &str) -> Result<Profile> {
    let u = parse_url(s)?;
    let (uuid, password) = user_info(&u);
    let (host, port, present) = host_port(&u)?;
    let port = apply_default_port(port, present, 443)?;
    let pairs = query_pairs(&u);
    let get = |k: &str| query_get(&pairs, k).unwrap_or("").to_string();
    if uuid.is_empty() {
        return Err(LinkError("tuic: не указан UUID".into()));
    }
    let detail = TuicDetail {
        uuid,
        password,
        congestion_control: get("congestion_control"),
        udp_relay_mode: get("udp_relay_mode"),
        sni: get("sni"),
        alpn: get("alpn"),
        allow_insecure: get("allow_insecure") == "1" || get("allowInsecure") == "1",
        disable_sni: get("disable_sni") == "1",
        ..Default::default()
    };
    Ok(Profile {
        r#type: ProfileType::Tuic,
        name: frag_name(&u),
        address: host,
        port,
        detail: Some(Detail::Tuic(detail)),
        ..Default::default()
    })
}
