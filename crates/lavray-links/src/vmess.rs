// SPDX-License-Identifier: GPL-3.0-only

//! Парсер vmess:// — URL-формат (XTLS#716); base64 JSON-ветка (v2rayN) в
//! vmess_json.rs. Паритет Go `links/parse.go parseVMess`. Фикс P1-1 (stream).

use crate::caps::VMESS_SECURITIES;
use crate::stream::{apply_stream_from_query, sni_from_host, validate_stream_caps};
use crate::util::{
    apply_default_port, check_field_len, decode_b64_strict, frag_name, host_port, parse_url,
    query_get, query_pairs, user_info, LinkError, Result, MAX_FIELD_LENGTH, MAX_REMARK_LENGTH,
};
use crate::vmess_json::{from_json, VmessJson};
use lavray_model::{Detail, Profile, ProfileType, StreamSettings, VMessDetail};

/// Разобрать vmess:// ссылку.
pub fn parse(s: &str) -> Result<Profile> {
    let rest = &s["vmess://".len()..];
    if let Some(bytes) = decode_b64_strict(rest) {
        let json: VmessJson = serde_json::from_slice(&bytes)
            .map_err(|e| LinkError(format!("vmess: base64-тело не JSON: {e}")))?;
        return from_json(&json);
    }
    from_url(s)
}

fn from_url(s: &str) -> Result<Profile> {
    let u = parse_url(s)?;
    let (uuid, _, _) = user_info(&u);
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
    if !VMESS_SECURITIES.contains(&scy.as_str()) {
        return Err(LinkError(format!(
            "vmess: шифрование {scy:?} не поддерживается"
        )));
    }

    let mut st = StreamSettings::default();
    apply_stream_from_query(&mut st, &pairs, "tls")
        .map_err(|e| LinkError(format!("vmess: {}", e.0)))?;
    validate_stream_caps(&st)?;
    let name = frag_name(&u);
    check_field_len("имя", &name, MAX_REMARK_LENGTH)?;
    let mut p = Profile {
        r#type: ProfileType::VMess,
        name,
        address: host,
        port,
        detail: Some(Detail::VMess(VMessDetail {
            uuid,
            alter_id: 0,
            security: scy,
        })),
        ..Default::default()
    };
    if st != StreamSettings::default() {
        sni_from_host(&p.address, &mut st);
        p.stream = Some(st);
    }
    Ok(p)
}
