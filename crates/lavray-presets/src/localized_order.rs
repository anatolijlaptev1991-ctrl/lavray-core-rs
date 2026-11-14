// SPDX-License-Identifier: GPL-3.0-only

//! Канонический порядок ключей `Localized` при маршале (SCHEMA §4): поставка
//! ru/zh/en/es/de, затем прочие по алфавиту — стабильный golden байт-в-байт.

use std::collections::BTreeMap;

/// Порядок поставки (SCHEMA: бренды не переводятся, говорящие имена — 5 языков).
const CANONICAL_LANGS: [&str; 5] = ["ru", "zh", "en", "es", "de"];

/// Канонический порядок ключей: поставка, затем прочие по алфавиту.
pub(crate) fn canonical_keys(map: &BTreeMap<String, String>) -> Vec<&str> {
    let mut keys: Vec<&str> = CANONICAL_LANGS
        .iter()
        .filter(|l| map.contains_key(**l))
        .copied()
        .collect();
    let rest: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|k| !CANONICAL_LANGS.contains(k))
        .collect();
    keys.extend(rest);
    keys
}
