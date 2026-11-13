// SPDX-License-Identifier: GPL-3.0-only

//! Определение страны сервера для группировки в UI (FR-UI-008/009, порт Go
//! `model/geo.go` DetectGeo). Каждый профиль получает ISO-код (ru/jp/nl/…) из
//! имени (эмодзи-флаг, код страны, англ./рус. название) или из домена/адреса.
//! Неизвестно — пусто.

use crate::geo_aliases::{alias_code, all_aliases};
use crate::geo_iso::{contains_alias, is_iso_country, is_not_country_tag};

/// Эмодзи-флаг (два regional indicator) → ISO-код.
fn flag_to_iso(name: &str) -> Option<String> {
    let runes: Vec<char> = name.chars().collect();
    for i in 0..runes.len().saturating_sub(1) {
        let (a, b) = (runes[i] as u32, runes[i + 1] as u32);
        if (0x1F1E6..=0x1F1FF).contains(&a) && (0x1F1E6..=0x1F1FF).contains(&b) {
            let ca = char::from_u32(a - 0x1F1E6 + 'A' as u32)?.to_ascii_lowercase();
            let cb = char::from_u32(b - 0x1F1E6 + 'A' as u32)?.to_ascii_lowercase();
            return Some(format!("{ca}{cb}"));
        }
    }
    None
}

/// Двухбуквенный код между разделителями (только настоящий код страны, не тег
/// протокола ws/ss/cf… — T-54).
fn code_between(s: &str, left: u8, right: u8) -> Option<String> {
    let b = s.as_bytes();
    if b.len() < 4 {
        return None;
    }
    for i in 0..=b.len() - 4 {
        if b[i] == left && b[i + 3] == right {
            let code = s[i + 1..i + 3].to_lowercase();
            if is_alpha2(&code) && is_iso_country(&code) && !is_not_country_tag(&code) {
                return Some(code);
            }
        }
    }
    None
}

fn is_alpha2(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|c| c.is_ascii_lowercase())
}

/// Определить ISO-код страны профиля по имени/адресу (FR-UI-008). Порядок:
/// эмодзи-флаг → явный код «[NL]»/«_nl_»/«-JP» → алиас названия в имени → TLD
/// адреса (.ru/.de), кроме общих (com/net/org/io).
#[must_use]
pub fn detect_geo(name: &str, address: &str) -> String {
    if let Some(code) = flag_to_iso(name) {
        return code;
    }
    for (l, r) in [(b'[', b']'), (b'(', b')'), (b'_', b'_'), (b'-', b'-')] {
        if let Some(code) = code_between(name, l, r) {
            return code;
        }
    }
    let lower = name.to_lowercase();
    // Алиасы — от длинных к коротким, чтобы «new zealand» не поймал «zealand».
    let mut best = "";
    let mut best_len = 0;
    for (alias, code) in all_aliases() {
        if alias.len() > best_len && contains_alias(&lower, alias) {
            best = code;
            best_len = alias.len();
        }
    }
    if !best.is_empty() {
        return best.to_string();
    }
    // TLD адреса (только двухбуквенные национальные, кроме служебных).
    if let Some(i) = address.rfind('.') {
        if i + 2 < address.len() {
            let tld = address[i + 1..].to_lowercase();
            if tld.len() == 2
                && alias_code(&tld).is_none()
                && !matches!(tld.as_str(), "io" | "to" | "me" | "tv" | "cc" | "ai")
            {
                return tld;
            }
        }
    }
    String::new()
}
