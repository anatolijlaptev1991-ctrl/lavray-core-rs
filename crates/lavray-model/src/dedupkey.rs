// SPDX-License-Identifier: GPL-3.0-only

//! Отпечаток «того же сервера» (порт Go `model/dedupkey.go`). Один ключ
//! используют импорт (пропуск уже имеющихся) и очистка дубликатов: два профиля
//! равны, если из них собирается один и тот же конфиг. В ключ входят тип,
//! адрес, порт, Detail, Stream и custom-поля; не входят имя, заметки, теги,
//! избранное, страна, тест, трафик, id, группа, времена. Ключ — sha256.

use crate::customhash::hex_encode;
use crate::Profile;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Префикс версии формулы: смена формулы меняет все ключи.
const DEDUP_DOMAIN: &[u8] = b"LAVDK1\x00";

/// Поля профиля, определяющие конфиг (порядок полей фиксирован, паритет Go).
#[derive(Serialize)]
struct DedupFields<'a> {
    r#type: crate::ProfileType,
    address: String,
    port: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "str::is_empty")]
    custom_outbound: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    custom_config: &'a str,
}

/// sha256 (64 hex) отпечатка профиля. Адрес — без регистра и крайних пробелов.
/// Пустая строка — отпечаток построить не удалось; профиль не считается дублем.
#[must_use]
pub fn dedup_key(p: &Profile) -> String {
    let fields = DedupFields {
        r#type: p.r#type,
        address: p.address.trim().to_lowercase(),
        port: p.port,
        detail: p.detail.as_ref().map(crate::Detail::to_value),
        stream: p.stream.as_ref().and_then(|s| serde_json::to_value(s).ok()),
        custom_outbound: &p.custom_outbound_json,
        custom_config: &p.custom_config_json,
    };
    let Ok(b) = serde_json::to_vec(&fields) else {
        return String::new();
    };
    let mut h = Sha256::new();
    h.update(DEDUP_DOMAIN);
    h.update(&b);
    hex_encode(&h.finalize())
}
