// SPDX-License-Identifier: GPL-3.0-only

//! Парсер trojan:// и vless:// (общий TrojanVLESSBean). Паритет с Go
//! `links/parse.go parseTrojanVLESS`: импорт stream (P1-1), flow-валидация (P2-4).

use crate::caps::VLESS_FLOWS;
use crate::stream::{apply_stream_from_query, sni_from_host, validate_stream_caps};
use crate::util::{
    apply_default_port, check_field_len, frag_name, host_port, parse_url, query_get, query_pairs,
    user_info, LinkError, Result, MAX_FIELD_LENGTH, MAX_REMARK_LENGTH,
};
use lavray_model::{Detail, Profile, ProfileType, StreamSettings, TrojanVlessDetail};

/// Разобрать trojan:// или vless:// ссылку.
pub fn parse(scheme: &str, s: &str) -> Result<Profile> {
    let u = parse_url(s)?;
    let (password, _, _) = user_info(&u);
    check_field_len("пароль", &password, MAX_FIELD_LENGTH)?;
    if password.is_empty() {
        return Err(LinkError(format!(
            "{scheme}: не указан {}",
            if scheme == "vless" {
                "UUID"
            } else {
                "пароль"
            }
        )));
    }
    let (host, port, present) = host_port(&u)?;
    let port = apply_default_port(port, present, 443)?;
    let pairs = query_pairs(&u);

    let mut detail = TrojanVlessDetail {
        password,
        flow: String::new(),
    };
    let mut st = StreamSettings::default();
    let def_sec = if scheme == "trojan" { "tls" } else { "" };
    apply_stream_from_query(&mut st, &pairs, def_sec)
        .map_err(|e| LinkError(format!("{scheme}: {}", e.0)))?;

    if scheme == "vless" {
        if let Some(v) = query_get(&pairs, "flow") {
            if !v.is_empty() && !VLESS_FLOWS.contains(&v) {
                return Err(LinkError(format!(
                    "{scheme}: flow {v:?} не поддерживается (допустимо: xtls-rprx-vision)"
                )));
            }
            detail.flow = v.to_string();
        }
    }
    validate_stream_caps(&st)?;
    let name = frag_name(&u);
    check_field_len("имя", &name, MAX_REMARK_LENGTH)?;

    let mut p = Profile {
        r#type: if scheme == "trojan" {
            ProfileType::Trojan
        } else {
            ProfileType::Vless
        },
        name,
        address: host,
        port,
        detail: Some(Detail::TrojanVless(detail)),
        ..Default::default()
    };
    if st != StreamSettings::default() {
        sni_from_host(&p.address, &mut st);
        p.stream = Some(st);
    }
    Ok(p)
}
