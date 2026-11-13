// SPDX-License-Identifier: GPL-3.0-only

//! Парсер hysteria2:// (hy2://) и tuic://. Паритет с Go `links/parse.go`
//! parseHysteria2/parseTUIC. Фикс P1-2 (пароль user:pass), P2-2/P2-3 (поля).

use crate::caps::{
    normalize_alpn, parse_bool_param, validate_duration, validate_server_ports, TUIC_CONGESTIONS,
    TUIC_RELAY_MODES,
};
use crate::util::{
    apply_default_port, check_field_len, frag_name, host_port, parse_url, query_get, query_pairs,
    user_info, LinkError, Result, MAX_FIELD_LENGTH, MAX_REMARK_LENGTH,
};
use lavray_model::{Detail, Hysteria2Detail, Profile, ProfileType, TuicDetail};

/// Разобрать hysteria2:// / hy2:// ссылку.
pub fn parse_hysteria2(s: &str) -> Result<Profile> {
    let u = parse_url(s)?;
    let (host, port, present) = host_port(&u)?;
    let port = apply_default_port(port, present, 443)?;
    let pairs = query_pairs(&u);
    let get = |k: &str| query_get(&pairs, k);

    // пароль: user[:pass] ⇒ user(+":"+pass); без пароля ⇒ весь userinfo (P1-2).
    let (user, pass, has_pass) = user_info(&u);
    let password = if has_pass && !pass.is_empty() {
        format!("{user}:{pass}")
    } else {
        user
    };
    check_field_len("пароль", &password, MAX_FIELD_LENGTH)?;
    if password.is_empty() {
        return Err(LinkError("hy2: не указан пароль".into()));
    }

    let mut d = Hysteria2Detail {
        password,
        ..Default::default()
    };
    if let Some(v) = get("obfs") {
        if !v.is_empty() && v != "salamander" {
            return Err(LinkError(format!(
                "hy2: obfs {v:?} не поддерживается (только salamander)"
            )));
        }
    }
    if let Some(v) = get("obfs-password") {
        check_field_len("obfs-password", v, MAX_FIELD_LENGTH)?;
        d.obfs_password = v.to_string();
    }
    if let Some(v) = get("mport") {
        validate_server_ports(v)?;
        d.server_ports = v.to_string();
    }
    if let Some(v) = get("insecure") {
        d.allow_insecure = parse_bool_param(v);
    }
    if let Some(v) = get("disable_sni") {
        d.disable_sni = parse_bool_param(v);
    }
    if let Some(v) = get("sni") {
        d.sni = v.trim().to_string();
    }
    if let Some(v) = get("alpn") {
        d.alpn = normalize_alpn(v);
    }
    if let Some(v) = get("hop_interval").filter(|v| !v.is_empty()) {
        validate_duration("hy2: hop_interval", v)?;
        d.hop_interval = v.to_string();
    }
    for (key, dst) in [
        ("upmbps", &mut d.upload_mbps),
        ("downmbps", &mut d.download_mbps),
    ] {
        if let Some(v) = get(key).filter(|v| !v.is_empty()) {
            let n: i64 = v
                .parse()
                .map_err(|_| LinkError(format!("hy2: {key} = {v:?}: ожидается число Мбит/с")))?;
            if !(0..=1_000_000).contains(&n) {
                return Err(LinkError(format!(
                    "hy2: {key} = {v:?}: ожидается число Мбит/с"
                )));
            }
            *dst = n;
        }
    }
    check_field_len("sni", &d.sni, MAX_FIELD_LENGTH)?;
    let name = frag_name(&u);
    check_field_len("имя", &name, MAX_REMARK_LENGTH)?;
    Ok(Profile {
        r#type: ProfileType::Hysteria2,
        name,
        address: host,
        port,
        detail: Some(Detail::Hysteria2(d)),
        ..Default::default()
    })
}

/// Разобрать tuic:// ссылку.
pub fn parse_tuic(s: &str) -> Result<Profile> {
    let u = parse_url(s)?;
    let (host, port, present) = host_port(&u)?;
    let port = apply_default_port(port, present, 443)?;
    let pairs = query_pairs(&u);
    let get = |k: &str| query_get(&pairs, k);

    let (uuid, password, _) = user_info(&u);
    if uuid.is_empty() {
        return Err(LinkError("tuic: не указан UUID".into()));
    }
    if password.is_empty() {
        return Err(LinkError("tuic: не указан пароль".into()));
    }
    check_field_len("uuid", &uuid, MAX_FIELD_LENGTH)?;
    check_field_len("пароль", &password, MAX_FIELD_LENGTH)?;

    let mut d = TuicDetail {
        uuid,
        password,
        ..Default::default()
    };
    if let Some(v) = get("congestion_control") {
        if !TUIC_CONGESTIONS.contains(&v) {
            return Err(LinkError(format!(
                "tuic: congestion_control {v:?} не поддерживается (bbr, cubic, new_reno)"
            )));
        }
        d.congestion_control = v.to_string();
    }
    if let Some(v) = get("udp_relay_mode") {
        if !TUIC_RELAY_MODES.contains(&v) {
            return Err(LinkError(format!(
                "tuic: udp_relay_mode {v:?} не поддерживается (native, quic)"
            )));
        }
        d.udp_relay_mode = v.to_string();
    }
    if let Some(v) = get("alpn") {
        d.alpn = normalize_alpn(v);
    }
    if let Some(v) = get("sni") {
        d.sni = v.trim().to_string();
    }
    if let Some(v) = get("allow_insecure") {
        d.allow_insecure = parse_bool_param(v);
    }
    if let Some(v) = get("disable_sni") {
        d.disable_sni = parse_bool_param(v);
    }
    if let Some(v) = get("zero_rtt_handshake") {
        d.zero_rtt_handshake = parse_bool_param(v);
    }
    if let Some(v) = get("heartbeat").filter(|v| !v.is_empty()) {
        validate_duration("tuic: heartbeat", v)?;
        d.heartbeat = v.to_string();
    }
    check_field_len("sni", &d.sni, MAX_FIELD_LENGTH)?;
    let name = frag_name(&u);
    check_field_len("имя", &name, MAX_REMARK_LENGTH)?;
    Ok(Profile {
        r#type: ProfileType::Tuic,
        name,
        address: host,
        port,
        detail: Some(Detail::Tuic(d)),
        ..Default::default()
    })
}
