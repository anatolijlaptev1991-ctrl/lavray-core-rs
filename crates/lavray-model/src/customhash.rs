// SPDX-License-Identifier: GPL-3.0-only

//! Хэш custom-содержимого профиля (T-08B, порт Go `model/customhash.go`).
//! Подтверждение custom-полей хранится как хэш и действует, пока содержимое не
//! изменилось: клиент не может «выставить флаг», любая правка снимает
//! подтверждение сама. H = sha256("LAVCF1\0" ‖ seg(outbound) ‖ 0 ‖ seg(config)
//! [‖ 0 ‖ canon(full_config) для internal-full]).

use crate::canonjson::{canonical_json, CanonError};
use crate::{is_internal_full, Detail, Profile};
use sha2::{Digest, Sha256};

/// Префикс версии формулы: смена формулы меняет все хэши.
const CUSTOM_HASH_DOMAIN: &[u8] = b"LAVCF1\x00";

/// Полный конфиг internal-full профиля ("" у остальных).
#[must_use]
pub fn internal_full_json(p: &Profile) -> String {
    if !is_internal_full(p) {
        return String::new();
    }
    match &p.detail {
        Some(Detail::Custom(d)) => d.full_config_json.clone(),
        _ => String::new(),
    }
}

/// Каноническое значение одного custom-поля; "{}" и пустой документ → "".
fn custom_segment(raw: &str) -> (String, Option<CanonError>) {
    match canonical_json(raw) {
        Ok(c) if c == "{}" => (String::new(), None),
        Ok(c) => (c, None),
        Err(e) => (String::new(), Some(e)),
    }
}

/// Хэш содержимого + есть ли что подтверждать; ошибка — поле не канонизируется.
fn custom_digest(p: &Profile) -> (String, bool, Option<CanonError>) {
    let (out, err_out) = custom_segment(&p.custom_outbound_json);
    let (cfg, err_cfg) = custom_segment(&p.custom_config_json);
    let full = is_internal_full(p);
    let has = full || !out.is_empty() || !cfg.is_empty() || err_out.is_some() || err_cfg.is_some();
    if let Some(e) = err_out {
        return (String::new(), has, Some(e));
    }
    if let Some(e) = err_cfg {
        return (String::new(), has, Some(e));
    }
    let mut h = Sha256::new();
    h.update(CUSTOM_HASH_DOMAIN);
    h.update(out.as_bytes());
    h.update([0u8]);
    h.update(cfg.as_bytes());
    if full {
        match canonical_json(&internal_full_json(p)) {
            Ok(canon) => {
                h.update([0u8]);
                h.update(canon.as_bytes());
            }
            Err(e) => return (String::new(), has, Some(e)),
        }
    }
    (hex_encode(&h.finalize()), has, None)
}

/// Есть ли у профиля что подтверждать (непустой custom_outbound/custom_config,
/// невалидный JSON тоже содержимое, или internal-full).
#[must_use]
pub fn has_custom_content(p: &Profile) -> bool {
    if is_internal_full(p) {
        return true;
    }
    if p.custom_outbound_json.trim().is_empty() && p.custom_config_json.trim().is_empty() {
        return false;
    }
    let (_, has, _) = custom_digest(p);
    has
}

/// sha256 (64 hex) custom-содержимого. Ошибка — поле не разбирается как JSON.
pub fn custom_fields_hash(p: &Profile) -> Result<String, CanonError> {
    let (h, _, err) = custom_digest(p);
    match err {
        Some(e) => Err(e),
        None => Ok(h),
    }
}

/// Подтверждено ли текущее содержимое: сохранённый custom_hash равен хэшу
/// текущего содержимого (пересчёт при каждом чтении).
#[must_use]
pub fn custom_confirmed(p: &Profile) -> bool {
    if p.custom_hash.is_empty() {
        return false;
    }
    let (h, has, err) = custom_digest(p);
    err.is_none() && has && h == p.custom_hash
}

/// Hex-кодирование байтов (нижний регистр).
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
