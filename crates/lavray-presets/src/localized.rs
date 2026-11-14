// SPDX-License-Identifier: GPL-3.0-only

//! `Localized` — map<lang, string> с каноническим порядком ключей при маршале
//! (ru, zh, en, es, de, затем прочие по алфавиту). Даёт байт-в-байт стабильный
//! golden — паритет с Go `presets.Localized.MarshalJSON`.

use crate::localized_order::canonical_keys;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;

/// Локализованная строка: язык → текст.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Localized(BTreeMap<String, String>);

impl Localized {
    /// Пустой набор.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Число языков.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Пуст ли набор.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Текст для языка.
    #[must_use]
    pub fn get(&self, lang: &str) -> Option<&str> {
        self.0.get(lang).map(String::as_str)
    }

    /// Вставить перевод.
    pub fn insert(&mut self, lang: impl Into<String>, text: impl Into<String>) {
        self.0.insert(lang.into(), text.into());
    }

    /// Итерация по парам (язык, текст) — паритет обхода map в Go.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }
}

impl Serialize for Localized {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for key in canonical_keys(&self.0) {
            map.serialize_entry(key, &self.0[key])?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Localized {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LocalizedVisitor;

        impl<'de> Visitor<'de> for LocalizedVisitor {
            type Value = Localized;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("map<lang, string>")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Localized, M::Error> {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<String, String>()? {
                    map.insert(key, value);
                }
                Ok(Localized(map))
            }
        }

        deserializer.deserialize_map(LocalizedVisitor)
    }
}

impl FromIterator<(String, String)> for Localized {
    fn from_iter<I: IntoIterator<Item = (String, String)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}
