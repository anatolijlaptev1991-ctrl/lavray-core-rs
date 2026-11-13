// SPDX-License-Identifier: GPL-3.0-only

//! Нормализованные алиасы → ISO 3166-1 alpha-2 (порт Go `model/geo.go`
//! geoAliases). Только ходовые для прокси-подписок страны; расширяется без
//! миграций. Данные разбиты на два файла ради трещотки размеров.

use crate::geo_aliases_b::GEO_ALIASES_B;

/// Алиасы, часть A (нижний регистр) → ISO-код.
pub const GEO_ALIASES_A: &[(&str, &str)] = &[
    ("россия", "ru"),
    ("рф", "ru"),
    ("russia", "ru"),
    ("russian", "ru"),
    ("москва", "ru"),
    ("moscow", "ru"),
    ("германия", "de"),
    ("germany", "de"),
    ("франкфурт", "de"),
    ("frankfurt", "de"),
    ("berlin", "de"),
    ("нидерланды", "nl"),
    ("netherlands", "nl"),
    ("holland", "nl"),
    ("amsterdam", "nl"),
    ("амстердам", "nl"),
    ("сша", "us"),
    ("usa", "us"),
    ("united states", "us"),
    ("america", "us"),
    ("new york", "us"),
    ("нью-йорк", "us"),
    ("финляндия", "fi"),
    ("finland", "fi"),
    ("helsinki", "fi"),
    ("хельсинки", "fi"),
    ("швеция", "se"),
    ("sweden", "se"),
    ("stockholm", "se"),
    ("стокгольм", "se"),
    ("япония", "jp"),
    ("japan", "jp"),
    ("tokyo", "jp"),
    ("токио", "jp"),
    ("osaka", "jp"),
    ("сингапур", "sg"),
    ("singapore", "sg"),
    ("китай", "cn"),
    ("china", "cn"),
    ("hong kong", "hk"),
    ("hongkong", "hk"),
    ("гонконг", "hk"),
    ("тайвань", "tw"),
    ("taiwan", "tw"),
    ("корея", "kr"),
    ("korea", "kr"),
    ("south korea", "kr"),
    ("seoul", "kr"),
    ("сеул", "kr"),
    ("турция", "tr"),
    ("turkey", "tr"),
    ("istanbul", "tr"),
    ("стамбул", "tr"),
    ("польша", "pl"),
    ("poland", "pl"),
    ("warsaw", "pl"),
    ("варшава", "pl"),
    ("чехия", "cz"),
    ("czech", "cz"),
    ("prague", "cz"),
    ("прага", "cz"),
    ("австрия", "at"),
    ("austria", "at"),
    ("vienna", "at"),
    ("вена", "at"),
    ("швейцария", "ch"),
    ("switzerland", "ch"),
    ("zurich", "ch"),
    ("цюрих", "ch"),
    ("великобритания", "gb"),
    ("uk", "gb"),
    ("united kingdom", "gb"),
    ("britain", "gb"),
    ("london", "gb"),
    ("лондон", "gb"),
    ("франция", "fr"),
    ("france", "fr"),
    ("paris", "fr"),
    ("париж", "fr"),
    ("италия", "it"),
    ("italy", "it"),
    ("milan", "it"),
    ("милан", "it"),
    ("испания", "es"),
    ("spain", "es"),
    ("madrid", "es"),
    ("мадрид", "es"),
];

/// Все алиасы (A + B) в порядке обхода.
pub fn all_aliases() -> impl Iterator<Item = (&'static str, &'static str)> {
    GEO_ALIASES_A.iter().chain(GEO_ALIASES_B.iter()).copied()
}

/// ISO-код по алиасу (или None).
pub fn alias_code(alias: &str) -> Option<&'static str> {
    all_aliases().find(|(a, _)| *a == alias).map(|(_, c)| c)
}
