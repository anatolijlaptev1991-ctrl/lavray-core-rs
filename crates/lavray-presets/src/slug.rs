// SPDX-License-Identifier: GPL-3.0-only

//! id пользовательских наборов: `custom:<slug>` (T-80, порт Go
//! `presets/slug.go`). Slug из имени: латиница в нижнем регистре, кириллица
//! транслитом, всё прочее — разделитель «-». Безопасен как часть id, ключ
//! мапы и имя файла.

const CUSTOM_ID_PREFIX: &str = "custom:";
const SLUG_MAX: usize = 48;
const SLUG_FALLBACK: &str = "set";
const MINT_LIMIT: u32 = 1 << 16;

/// Кириллица и частые латинские буквы с диакритикой → ASCII.
fn translit(r: char) -> Option<&'static str> {
    let s = match r {
        'а' | 'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => "a",
        'æ' => "ae",
        'ç' => "c",
        'б' => "b",
        'в' => "v",
        'г' | 'ґ' => "g",
        'д' => "d",
        'е' | 'ё' | 'è' | 'é' | 'ê' | 'ë' | 'э' => "e",
        'ж' => "zh",
        'з' => "z",
        'и' | 'і' | 'ì' | 'í' | 'î' | 'ï' => "i",
        'й' | 'ы' | 'ý' | 'ÿ' => "y",
        'к' => "k",
        'л' => "l",
        'м' => "m",
        'н' | 'ñ' => "n",
        'о' | 'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' | 'ù' | 'ú' | 'û' | 'ü' => "u",
        'ф' => "f",
        'х' => "kh",
        'ц' => "ts",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "shch",
        'ъ' | 'ь' => "",
        'ю' => "yu",
        'я' => "ya",
        'ї' => "yi",
        'є' => "ye",
        'œ' => "oe",
        'ß' => "ss",
        _ => return None,
    };
    Some(s)
}

/// Имя → slug: только [a-z0-9-], без «-» по краям и подряд, 1..48 символов.
/// Имя без пригодных символов даёт "set".
#[must_use]
pub fn slugify(name: &str) -> String {
    let mut sb = String::new();
    let mut sep = true; // «-» в начале не нужен
    for r in name.to_lowercase().chars() {
        if let Some(tr) = translit(r) {
            for c in tr.chars() {
                if c.is_ascii_lowercase() || c.is_ascii_digit() {
                    sb.push(c);
                    sep = false;
                } else if !sep {
                    sb.push('-');
                    sep = true;
                }
            }
        } else if (r as u32) < 0x80 {
            for c in r.to_string().chars() {
                if c.is_ascii_lowercase() || c.is_ascii_digit() {
                    sb.push(c);
                    sep = false;
                } else if !sep {
                    sb.push('-');
                    sep = true;
                }
            }
        } else if !sep {
            // прочие письменности (иероглифы и т.п.) — разделитель
            sb.push('-');
            sep = true;
        }
    }
    cut_slug(sb, SLUG_MAX)
}

fn cut_slug(mut s: String, max: usize) -> String {
    if s.len() > max {
        s = s[..max].to_string();
    }
    let trimmed = s.trim_matches('-').to_string();
    if trimmed.is_empty() {
        return SLUG_FALLBACK.into();
    }
    trimmed
}

/// Выдаёт свободный id `custom:<slug>`: при коллизии добавляет -2, -3…
/// (суффикс укладывается в SlugMax, свободная «дырка» занимается первой).
/// `taken` сообщает, занят ли id; чистая функция — состояния не хранит.
#[must_use]
pub fn mint_id(name: &str, taken: &dyn Fn(&str) -> bool) -> String {
    let base = slugify(name);
    let plain = format!("{CUSTOM_ID_PREFIX}{base}");
    if !taken(&plain) {
        return plain;
    }
    for n in 2..MINT_LIMIT {
        let suffix = format!("-{n}");
        let keep = SLUG_MAX.saturating_sub(suffix.len());
        let mut head = base[..base.len().min(keep)].trim_matches('-').to_string();
        if head.is_empty() {
            head = SLUG_FALLBACK.into();
        }
        let id = format!("{CUSTOM_ID_PREFIX}{head}{suffix}");
        if !taken(&id) {
            return id;
        }
    }
    format!("{CUSTOM_ID_PREFIX}{base}-{MINT_LIMIT}")
}
