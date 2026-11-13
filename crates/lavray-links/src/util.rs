// SPDX-License-Identifier: GPL-3.0-only

//! Утилиты разбора ссылок: base64 (строгий/URL-safe), query, host/port, имя.
//! Паритет с Go `links/util.go` + `parse.go` (hostPort/fragName/userInfo).

use base64::Engine;
use thiserror::Error;
use url::Url;

/// Ошибка разбора ссылки.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct LinkError(pub String);

/// Результат разбора ссылки.
pub type Result<T> = std::result::Result<T, LinkError>;

/// Максимальная длина ссылки (байт).
pub const MAX_LINK_LENGTH: usize = 64 * 1024;
/// Максимальная длина поля (байт).
pub const MAX_FIELD_LENGTH: usize = 4096;

/// Строгий base64 (standard, с padding) — v2rayN-формат vmess.
pub fn decode_b64_strict(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
}

/// URL-safe base64 без padding (SIP002 ss, v2rayN raw).
pub fn decode_b64_url(s: &str) -> Option<Vec<u8>> {
    let t = s.trim();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(t)
        .ok()
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(t).ok())
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(t).ok())
}

/// Разобрать URL-подобную ссылку.
pub fn parse_url(s: &str) -> Result<Url> {
    Url::parse(s).map_err(|e| LinkError(format!("некорректный URL: {e}")))
}

/// Имя из фрагмента (`#name`), URL-декодированное.
pub fn frag_name(u: &Url) -> String {
    u.fragment().map(percent_decode).unwrap_or_default()
}

/// Пары query в порядке следования (дубликаты сохраняются).
pub fn query_pairs(u: &Url) -> Vec<(String, String)> {
    u.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Первое значение query-ключа.
pub fn query_get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Хост и порт из URL; present=false — порт отсутствует.
pub fn host_port(u: &Url) -> Result<(String, i64, bool)> {
    let host = u
        .host_str()
        .ok_or_else(|| LinkError("не указан хост".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if host.is_empty() {
        return Err(LinkError("не указан хост".into()));
    }
    match u.port() {
        Some(p) => Ok((host, i64::from(p), true)),
        None => Ok((host, 0, false)),
    }
}

/// userinfo: username и password (password может отсутствовать).
pub fn user_info(u: &Url) -> (String, String) {
    let user = percent_decode(u.username());
    let pass = u.password().map(percent_decode).unwrap_or_default();
    (user, pass)
}

///.Percent-декодирование строки.
pub fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Применить порт по умолчанию, если он отсутствует.
pub fn apply_default_port(port: i64, present: bool, default: i64) -> Result<i64> {
    if !present {
        return Ok(default);
    }
    if port <= 0 || port > 65535 {
        return Err(LinkError(format!("порт {port} вне 1…65535")));
    }
    Ok(port)
}

/// Проверка длины поля.
pub fn check_field_len(field: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        return Err(LinkError(format!("{field}: длиннее {max} байт")));
    }
    Ok(())
}
