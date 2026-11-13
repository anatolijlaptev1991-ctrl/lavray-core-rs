// SPDX-License-Identifier: GPL-3.0-only

//! Утилиты разбора ссылок (паритет Go `links/util.go` + `parse.go`): base64
//! строгий padded (Std+URL), query без «+»→пробел (QUrlQuery), host/port,
//! лимиты LNB-12/17, канонизация хоста.

use base64::Engine;
use thiserror::Error;
use url::Url;

/// Ошибка разбора ссылки.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct LinkError(pub String);

/// Результат разбора ссылки.
pub type Result<T> = std::result::Result<T, LinkError>;

/// Лимиты входа (LNB-12/17, паритет Go).
pub const MAX_LINK_LENGTH: usize = 64 * 1024;
/// Пароли/логины/uuid/sni/метод/отпечаток…
pub const MAX_FIELD_LENGTH: usize = 1024;
/// Имя/замечание профиля.
pub const MAX_REMARK_LENGTH: usize = 4096;
/// plugin-строка ss.
pub const MAX_PLUGIN_LENGTH: usize = 2048;
/// extra-параметр XHTTP.
pub const MAX_XHTTP_EXTRA: usize = 8192;

/// Строгий padded base64 (Std или URL-алфавит); \r\n и пустой вход отвергаются,
/// без trim (паритет Go decodeB64Strict, deviations.yaml).
pub fn decode_b64_strict(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.contains(['\r', '\n']) {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(s).ok())
}

/// padded или raw base64 (std/url) — для neko-ссылок без padding.
pub fn decode_b64_any(s: &str) -> Option<Vec<u8>> {
    decode_b64_strict(s)
        .or_else(|| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(s)
                .ok()
        })
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .ok()
        })
}

/// Разобрать URL-подобную ссылку.
pub fn parse_url(s: &str) -> Result<Url> {
    Url::parse(s).map_err(|e| LinkError(format!("некорректный URL: {e}")))
}

/// Имя из фрагмента (`#name`), URL-декодированное.
pub fn frag_name(u: &Url) -> String {
    u.fragment().map(percent_decode).unwrap_or_default()
}

/// Пары query из RawQuery вручную: %XX декодируется БЕЗ «+»→пробел (QUrlQuery /
/// Go url.PathUnescape), порядок сохраняется (паритет Go parseQuery).
pub fn query_pairs(u: &Url) -> Vec<(String, String)> {
    let Some(raw) = u.query() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for part in raw.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k, v),
            None => (part, ""),
        };
        out.push((percent_decode(k), percent_decode(v)));
    }
    out
}

/// Первое значение query-ключа (first-occurrence-wins, queryItemValue Qt).
pub fn query_get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Хост и порт из URL; present=false — порт отсутствует. IPv6-зона (%25)
/// отвергается (roundtrip-инвариант Go), хост канонизируется.
pub fn host_port(u: &Url) -> Result<(String, i64, bool)> {
    let raw = u
        .host_str()
        .ok_or_else(|| LinkError("не указан хост".into()))?;
    if raw.contains("%25") || raw.contains('%') {
        return Err(LinkError("IPv6 zone id не поддерживается в адресе".into()));
    }
    let host = canonical_host(raw);
    if host.is_empty() {
        return Err(LinkError("не указан хост".into()));
    }
    match u.port() {
        Some(p) => Ok((host, i64::from(p), true)),
        None => Ok((host, 0, false)),
    }
}

/// userinfo: (username, password, has_pass). password URL-декодирован.
pub fn user_info(u: &Url) -> (String, String, bool) {
    let user = percent_decode(u.username());
    match u.password() {
        Some(p) => (user, percent_decode(p), true),
        None => (user, String::new(), false),
    }
}

/// Percent-декодирование строки (без «+»→пробел).
pub fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Применить порт по умолчанию, если отсутствует; present-порт валидируется.
pub fn apply_default_port(port: i64, present: bool, default: i64) -> Result<i64> {
    if !present {
        return Ok(default);
    }
    require_port(port)
}

/// Порт в диапазоне 1..65535 (LNB-15: порт 0 никогда не попадает в модель).
pub fn require_port(port: i64) -> Result<i64> {
    if !(1..=65535).contains(&port) {
        return Err(LinkError(format!("порт {port} вне диапазона 1–65535")));
    }
    Ok(port)
}

/// Проверка длины поля (LNB-17).
pub fn check_field_len(field: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        return Err(LinkError(format!("поле {field} длиннее {max} байт")));
    }
    Ok(())
}

/// Канонизация хоста: IPv6-литерал (возможно в скобках) → сжатая форма;
/// домен — как есть (паритет Go canonicalHost).
pub fn canonical_host(h: &str) -> String {
    let inner = h
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(h);
    if let Ok(ip) = inner.parse::<std::net::IpAddr>() {
        return ip.to_string();
    }
    h.to_string()
}

/// Хост является IP-литералом (v4/v6).
pub fn is_ip_addr(h: &str) -> bool {
    h.parse::<std::net::IpAddr>().is_ok()
}

/// Экранирует всё, кроме unreserved (RFC 3986 §2.3: ALPHA/DIGIT/-._~).
/// Аналог Qt QUrl::toPercentEncoding: пробел → %20, «+» не используется
/// (паритет Go percentEncodeAll).
pub fn percent_encode_all(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
            out.push(c as char);
        } else {
            out.push('%');
            out.push(HEX[(c >> 4) as usize] as char);
            out.push(HEX[(c & 0xf) as usize] as char);
        }
    }
    out
}

/// base64url c padding (QByteArray::toBase64(Base64UrlEncoding), паритет Go
/// encodeB64URL).
pub fn encode_b64_url(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE.encode(s)
}
