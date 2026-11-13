// SPDX-License-Identifier: GPL-3.0-only

//! vmess:// base64 JSON-ветка (v2rayN). Паритет Go `links/parse.go
//! vmessFromJSON`. Вынесено из vmess.rs ради трещотки размеров. Фикс P1-3
//! (порт 0), P2-5 (aid 0..65535), P1-1 (stream-импорт из JSON).

use crate::caps::{
    canonical_network, normalize_alpn, normalize_security_none, NETWORKS, UTLS_FPS,
    VMESS_SECURITIES,
};
use crate::stream::{sni_from_host, validate_stream_caps};
use crate::util::{
    canonical_host, check_field_len, require_port, LinkError, Result, MAX_FIELD_LENGTH,
    MAX_REMARK_LENGTH,
};
use lavray_model::{Detail, Profile, ProfileType, StreamSettings, VMessDetail};
use serde::Deserialize;

/// v2rayN JSON-тело vmess-ссылки (поля потока — паритет Go vmessJSON).
#[derive(Debug, Deserialize)]
pub(crate) struct VmessJson {
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
    #[serde(default)]
    net: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    sni: String,
    #[serde(default)]
    alpn: String,
    #[serde(default)]
    fp: String,
    #[serde(default)]
    pbk: String,
    #[serde(default)]
    sid: String,
    #[serde(default)]
    spx: String,
}

/// Разобрать vmess JSON-тело в профиль.
pub(crate) fn from_json(j: &VmessJson) -> Result<Profile> {
    if j.add.trim().is_empty() {
        return Err(LinkError("vmess: не указан адрес сервера (add)".into()));
    }
    let port = any_to_int("port", &j.port)?;
    if j.id.is_empty() {
        return Err(LinkError("vmess: не указан UUID (id)".into()));
    }
    check_field_len("uuid", &j.id, MAX_FIELD_LENGTH)?;
    let mut aid = 0i64;
    if !j.aid.is_null() {
        aid = any_to_int("aid", &j.aid)?;
        if !(0..=65535).contains(&aid) {
            return Err(LinkError(format!(
                "vmess: aid = {aid} вне диапазона 0..65535"
            )));
        }
    }
    let scy = if j.scy.trim().is_empty() {
        "auto"
    } else {
        j.scy.as_str()
    };
    if !VMESS_SECURITIES.contains(&scy) {
        return Err(LinkError(format!(
            "vmess: шифрование {scy:?} не поддерживается"
        )));
    }

    let mut st = StreamSettings::default();
    let netw = canonical_network(j.net.trim().to_lowercase().as_str());
    if !netw.is_empty() && !NETWORKS.contains(&netw.as_str()) {
        return Err(LinkError(format!("vmess: сеть {netw:?} не поддерживается")));
    }
    st.network = netw;
    st.host.clone_from(&j.host);
    st.path.clone_from(&j.path);
    st.header_type.clone_from(&j.r#type);
    st.security = normalize_security_none(&j.tls)
        .map_err(|e| LinkError(format!("vmess: tls = {:?}: {}", j.tls, e.0)))?;
    st.sni = j.sni.trim().to_string();
    st.alpn = normalize_alpn(&j.alpn);
    if !j.fp.is_empty() && !UTLS_FPS.contains(&j.fp.as_str()) {
        return Err(LinkError(format!(
            "vmess: отпечаток uTLS {:?} не поддерживается",
            j.fp
        )));
    }
    st.utls_fingerprint.clone_from(&j.fp);
    st.reality_public_key.clone_from(&j.pbk);
    st.reality_short_id.clone_from(&j.sid);
    st.reality_spx.clone_from(&j.spx);
    if !st.reality_public_key.is_empty() {
        st.security = "reality".into();
    }
    validate_stream_caps(&st)?;

    let name = j.ps.clone();
    check_field_len("имя", &name, MAX_REMARK_LENGTH)?;
    let address = canonical_host(&j.add);
    let port = require_port(port)?;
    let mut p = Profile {
        r#type: ProfileType::VMess,
        name,
        address,
        port,
        detail: Some(Detail::VMess(VMessDetail {
            uuid: j.id.clone(),
            alter_id: aid,
            security: scy.to_string(),
        })),
        ..Default::default()
    };
    if st != StreamSettings::default() {
        sni_from_host(&p.address, &mut st);
        p.stream = Some(st);
    }
    Ok(p)
}

/// Порт/aid числом ИЛИ строкой; Null/отсутствие — ошибка (LNB-17, паритет Go
/// anyToInt: мусор не превращается в 0). Пустая строка aid → 0 (L2-3).
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
        serde_json::Value::Null => Err(LinkError(format!("vmess: поле {field} отсутствует"))),
        _ => Err(LinkError(format!("vmess: {field} имеет неверный тип"))),
    }
}
