// SPDX-License-Identifier: GPL-3.0-only

//! Парсер ss:// — SIP002 (`base64(method:password)@host:port`) и v2rayN
//! (`base64(method:password@host:port)`). Паритет с Go `links/parse.go parseSS`.

use crate::util::{
    check_field_len, decode_b64_strict, decode_b64_url, frag_name, host_port, parse_url, query_get,
    query_pairs, user_info, LinkError, Result, MAX_FIELD_LENGTH,
};
use lavray_model::{Detail, Profile, ProfileType, ShadowsocksDetail};

/// Поддерживаемые методы шифрования SS (LNB-17).
const METHODS: [&str; 12] = [
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
    "plain",
    "aes-128-cfb",
    "aes-256-cfb",
];

/// Разобрать ss:// ссылку.
pub fn parse(s: &str) -> Result<Profile> {
    let body = &s["ss://".len()..];
    let no_frag = body.split('#').next().unwrap_or(body);

    let (mut profile, detail) = if no_frag.contains('@') {
        parse_sip002(s)?
    } else {
        parse_v2rayn(body)?
    };

    if detail.password.is_empty() {
        return Err(LinkError("ss: не указан пароль".into()));
    }
    check_field_len("пароль", &detail.password, MAX_FIELD_LENGTH)?;
    if !METHODS.contains(&detail.method.as_str()) {
        return Err(LinkError(format!(
            "ss: метод {:?} не поддерживается",
            detail.method
        )));
    }
    profile.detail = Some(Detail::Shadowsocks(detail));
    Ok(profile)
}

/// SIP002: `ss://[base64url(method:password)|method:password]@host:port`.
fn parse_sip002(s: &str) -> Result<(Profile, ShadowsocksDetail)> {
    let u = parse_url(s)?;
    let (host, port, present) = host_port(&u)?;
    if !present {
        return Err(LinkError("ss: не указан порт".into()));
    }
    let (user, pass) = user_info(&u);
    let (method, password) = if pass.is_empty() {
        // userinfo = base64url(method:password)
        let bytes = decode_b64_url(&user)
            .or_else(|| decode_b64_strict(&user))
            .ok_or_else(|| LinkError("ss: некорректный base64 в userinfo".into()))?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        split_method_password(&text)?
    } else {
        (user, pass)
    };
    let pairs = query_pairs(&u);
    let plugin = query_get(&pairs, "plugin")
        .map(|v| v.replace("simple-obfs;", "obfs-local;"))
        .unwrap_or_default();
    Ok((
        Profile {
            r#type: ProfileType::Shadowsocks,
            name: frag_name(&u),
            address: host,
            port,
            ..Default::default()
        },
        ShadowsocksDetail {
            method,
            password,
            plugin,
            udp_over_tcp: 0,
        },
    ))
}

/// v2rayN: `ss://BASE64(method:password@host:port)#name`.
fn parse_v2rayn(body: &str) -> Result<(Profile, ShadowsocksDetail)> {
    let no_frag = body.split('#').next().unwrap_or(body);
    let bytes = decode_b64_strict(no_frag)
        .or_else(|| decode_b64_url(no_frag))
        .ok_or_else(|| LinkError("ss: некорректный base64 (формат v2rayN)".into()))?;
    let mut link = String::from_utf8_lossy(&bytes).into_owned();
    if let Some(i) = body.find('#') {
        link.push('#');
        link.push_str(&body[i + 1..]);
    }
    let u = parse_url(&format!("ss://{link}"))?;
    let (host, port, present) = host_port(&u)?;
    if !present {
        return Err(LinkError("ss: не указан порт".into()));
    }
    let (method, password) = user_info(&u);
    let pairs = query_pairs(&u);
    let plugin = query_get(&pairs, "plugin")
        .map(|v| v.replace("simple-obfs;", "obfs-local;"))
        .unwrap_or_default();
    Ok((
        Profile {
            r#type: ProfileType::Shadowsocks,
            name: frag_name(&u),
            address: host,
            port,
            ..Default::default()
        },
        ShadowsocksDetail {
            method,
            password,
            plugin,
            udp_over_tcp: 0,
        },
    ))
}

fn split_method_password(text: &str) -> Result<(String, String)> {
    let (m, pw) = text
        .split_once(':')
        .ok_or_else(|| LinkError("ss: в userinfo нет пары «метод:пароль»".into()))?;
    if m.is_empty() || pw.is_empty() {
        return Err(LinkError("ss: в userinfo нет пары «метод:пароль»".into()));
    }
    Ok((m.to_string(), pw.to_string()))
}
