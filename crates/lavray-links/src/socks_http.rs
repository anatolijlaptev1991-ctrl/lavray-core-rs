// SPDX-License-Identifier: GPL-3.0-only

//! Парсер socks:// (socks4/4a/5) и http:// / https://. Паритет с Go
//! `links/parse.go parseSocksHTTP`. Фикс P2-6: proto http/socks4 (не
//! https/socks4a), base64-логин v2rayN, stream security/sni, https⇒tls.

use crate::caps::normalize_security_none;
use crate::util::{
    apply_default_port, check_field_len, decode_b64_strict, frag_name, host_port, parse_url,
    query_get, query_pairs, user_info, LinkError, Result, MAX_FIELD_LENGTH, MAX_REMARK_LENGTH,
};
use lavray_model::{Detail, Profile, ProfileType, SocksHttpDetail, StreamSettings};

/// Разобрать socks/http/https ссылку.
pub fn parse(scheme: &str, s: &str) -> Result<Profile> {
    let u = parse_url(s)?;
    let (host, port, present) = host_port(&u)?;
    let (mut username, mut password, _) = user_info(&u);

    let (ptype, proto, default_port) = match scheme {
        "socks" | "socks5" => (ProfileType::Socks, "socks5", 1080),
        "socks4" | "socks4a" => (ProfileType::Socks, "socks4", 1080),
        "http" => (ProfileType::Http, "http", 80),
        "https" => (ProfileType::Http, "http", 443),
        _ => return Err(LinkError(format!("неподдерживаемая схема {scheme:?}"))),
    };
    let port = apply_default_port(port, present, default_port)?;

    // v2rayN-формат socks: пароля нет, логин — base64 «user:pass». Декодируем
    // только если результат — корректный UTF-8 с «:», иначе логин как есть.
    if password.is_empty() && !username.is_empty() {
        if let Some(b) = decode_b64_strict(&username) {
            if let Ok(dec) = String::from_utf8(b) {
                if let Some((u1, p1)) = dec.split_once(':') {
                    username = u1.to_string();
                    password = p1.to_string();
                }
            }
        }
    }
    check_field_len("username", &username, MAX_FIELD_LENGTH)?;
    check_field_len("password", &password, MAX_FIELD_LENGTH)?;

    // stream: security + sni (читает NekoBox; LAVRay и экспортирует).
    let pairs = query_pairs(&u);
    let mut st = StreamSettings::default();
    if let Some(v) = query_get(&pairs, "security") {
        st.security = normalize_security_none(v)?;
    }
    if scheme == "https" {
        st.security = "tls".into();
    }
    if let Some(v) = query_get(&pairs, "sni") {
        st.sni = v.trim().to_string();
    }

    let name = frag_name(&u);
    check_field_len("имя", &name, MAX_REMARK_LENGTH)?;
    let mut p = Profile {
        r#type: ptype,
        name,
        address: host,
        port,
        detail: Some(Detail::SocksHttp(SocksHttpDetail {
            proto: proto.to_string(),
            username,
            password,
        })),
        ..Default::default()
    };
    if st != StreamSettings::default() {
        p.stream = Some(st);
    }
    Ok(p)
}
