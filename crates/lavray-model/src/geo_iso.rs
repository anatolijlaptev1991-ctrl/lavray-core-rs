// SPDX-License-Identifier: GPL-3.0-only

//! Вспомогательные таблицы DetectGeo (T-54, B2-21, порт Go `model/geo_iso.go`):
//! ложные срабатывания «vless-ws-cdn → Самоа», «Fukuoka → GB».

/// Все 249 кодов ISO 3166-1 alpha-2 (нижний регистр). Явный код страны в имени
/// сервера принимается, только если это настоящий код.
const ISO_COUNTRY_CODES: &[&str] = &[
    "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as", "at", "au", "aw", "ax", "az",
    "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bl", "bm", "bn", "bo", "bq", "br", "bs",
    "bt", "bv", "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn",
    "co", "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "ee",
    "eg", "eh", "er", "es", "et", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gb", "gd", "ge", "gf",
    "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm",
    "hn", "hr", "ht", "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it", "je", "jm",
    "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc",
    "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mf", "mg", "mh", "mk",
    "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na",
    "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe", "pf", "pg",
    "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py", "qa", "re", "ro", "rs", "ru", "rw",
    "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr", "ss",
    "st", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to",
    "tr", "tt", "tv", "tw", "tz", "ua", "ug", "um", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi",
    "vn", "vu", "wf", "ws", "ye", "yt", "za", "zm", "zw",
];

/// Двухбуквенные теги протоколов/транспорта, совпадающие с кодами стран:
/// ws (WebSocket, Самоа), ss (Shadowsocks, Южный Судан), cf (Cloudflare, ЦАР),
/// tg (Telegram, Того), tc (TCP, Тёркс и Кайкос).
const NOT_COUNTRY_TAGS: &[&str] = &["ws", "ss", "cf", "tg", "tc"];

/// Является ли код настоящим кодом страны ISO.
pub fn is_iso_country(code: &str) -> bool {
    ISO_COUNTRY_CODES.contains(&code)
}

/// Является ли код тегом протокола (не страной).
pub fn is_not_country_tag(code: &str) -> bool {
    NOT_COUNTRY_TAGS.contains(&code)
}

/// Алиас входит в имя (lower — имя в нижнем регистре). Короткие алиасы
/// (≤ 3 символов: uk, usa, uae, рф…) совпадают только целым словом, иначе
/// «Fukuoka» давал uk → GB, «Busan» — usa → US. Цифры/знаки словом не считаются.
/// Длинные алиасы ищутся подстрокой («JapanTokyo»).
pub fn contains_alias(lower: &str, alias: &str) -> bool {
    if alias.chars().count() > 3 {
        return lower.contains(alias);
    }
    let chars: Vec<char> = lower.chars().collect();
    let alen = alias.chars().count();
    let mut from = 0;
    while from < chars.len() {
        let Some(rel) = find_sub(&chars[from..], alias) else {
            return false;
        };
        let start = from + rel;
        let end = start + alen;
        let before = if start > 0 {
            Some(chars[start - 1])
        } else {
            None
        };
        let after = chars.get(end).copied();
        let before_letter = before.is_some_and(char::is_alphabetic);
        let after_letter = after.is_some_and(char::is_alphabetic);
        if !before_letter && !after_letter {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Позиция подстроки alias в срезе символов (в символах).
fn find_sub(chars: &[char], alias: &str) -> Option<usize> {
    let a: Vec<char> = alias.chars().collect();
    if a.is_empty() || chars.len() < a.len() {
        return None;
    }
    (0..=chars.len() - a.len()).find(|&i| chars[i..i + a.len()] == a[..])
}
