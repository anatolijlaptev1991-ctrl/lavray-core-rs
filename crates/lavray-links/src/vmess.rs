// SPDX-License-Identifier: GPL-3.0-only

//! Парсер vmess:// — base64 JSON (v2rayN) и URL-формат (XTLS#716).
//! Паритет с Go `links/parse.go parseVMess/vmessFromJSON`.

use crate::util::{
    apply_default_port, check_field_len, decode_b64_strict, frag_name, host_port, parse_url,
    query_get, query_pairs, user_info, LinkError, Result, MAX_FIELD_LENGTH,
};
use lavray_model::{Detail, Profile, ProfileType, VMessDetail};
use serde::Deserialize;

/// v2rayN JSON-тело vmess-ссылки.
#[derive(Debug, Deserialize)]
struct VmessJson {
    #[serde(default)]
    ps: String,
    #[serde(default)]
    add: String,
    #[serde(default)]
    port: serde_json::Value,
    #[serde(default)]
    id: String,
    #[serde(default)]
    aid: serde_json::Value,
    #[serde(default)]
    scy: String,
}

/// Допустимые шифрования VMess.
const SECURITIES: [&str; 5] = ["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"];

/// Разобрать vmess:// ссылку.
pub fn parse(s: &str) -> Result<Profile> {
    let rest = &s["vmess://".len()..];
    // v2rayN: строгий base64 JSON.
    if let Some(bytes) = decode_b64_strict(rest) {
        let json: VmessJson = serde_json::from_slice(&bytes)
            .map_err(|e| LinkError(format!("vmess: base64-тело не JSON: {e}")))?;
        return from_json(&json);
    }
    from_url(s)
}

fn from_json(j: &VmessJson) -> Result<Profile> {
    if j.add.trim().is_empty() {
        return Err(LinkError("vmess: не указан адрес сервера (add)".into()));
    }
    let port = any_to_int("port", &j.port)?;
    let aid = any_to_int("aid", &j.aid)?;
    if j.id.is_empty() {
        return Err(LinkError("vmess: не указан UUID (id)".into()));
    }
    let scy = if j.scy.is_empty() {
        "auto"
    } else {
        j.scy.as_str()
    };
    if !SECURITIES.contains(&scy) {
        return Err(LinkError(format!(
            "vmess: шифрование {scy:?} не поддерживается"
        )));
    }
    Ok(Profile {
        r#type: ProfileType::VMess,
        name: j.ps.clone(),
        address: j.add.trim().to_string(),
        port,
        detail: Some(Detail::VMess(VMessDetail {
            uuid: j.id.clone(),
            alter_id: aid,
            security: scy.to_string(),
        })),
        ..Default::default()
    })
}

fn from_url(s: &str) -> Result<Profile> {
    let u = parse_url(s)?;
    let (uuid, _) = user_info(&u);
    check_field_len("uuid", &uuid, MAX_FIELD_LENGTH)?;
    if uuid.is_empty() {
        return Err(LinkError("vmess: не указан UUID".into()));
    }
    let (host, port, present) = host_port(&u)?;
    let port = apply_default_port(port, present, 443)?;
    let pairs = query_pairs(&u);
    let scy = query_get(&pairs, "encryption")
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map_or_else(|| "auto".to_string(), str::to_lowercase);
    if !SECURITIES.contains(&scy.as_str()) {
        return Err(LinkError(format!(
            "vmess: шифрование {scy:?} не поддерживается"
        )));
    }
    Ok(Profile {
        r#type: ProfileType::VMess,
        name: frag_name(&u),
        address: host,
        port,
        detail: Some(Detail::VMess(VMessDetail {
            uuid,
            alter_id: 0,
            security: scy,
        })),
        ..Default::default()
    })
}

/// Порт/aid приходят числом ИЛИ строкой (LNB-17: мусор отвергается).
fn any_to_int(field: &str, v: &serde_json::Value) -> Result<i64> {
    match v {
        serde_json::Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| LinkError(format!("vmess: {field} не целое"))),
        serde_json::Value::String(s) if s.trim().is_empty() => Ok(0),
        serde_json::Value::String(s) => s
            .trim()
            .parse::<i64>()
            .map_err(|_| LinkError(format!("vmess: {field} {s:?} не число"))),
        serde_json::Value::Null => Ok(0),
        _ => Err(LinkError(format!("vmess: {field} не число"))),
    }
}
