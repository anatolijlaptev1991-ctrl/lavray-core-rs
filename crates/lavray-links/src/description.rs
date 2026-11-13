// SPDX-License-Identifier: GPL-3.0-only

//! Служебный хвост имени «?serverDescription=<base64>» (0.2.1, порт Go
//! `links/description.go`). Панели подписок дописывают к имени описание сервера
//! (UTF-8 в base64). Хвост отрезается от имени, описание попадает в заметки.
//! Некорректный base64 — хвост просто отрезается. Фикс P2-11 аудита.

use crate::util::percent_decode;
use base64::Engine;
use lavray_model::Profile;

const DESCRIPTION_MARKER: &str = "?serverDescription=";
const DESCRIPTION_MARKER_ENCODED: &str = "%3FserverDescription%3D";
const MAX_DESCRIPTION_LENGTH: usize = 2048;

/// Позиция последнего вхождения ASCII-маркера без учёта регистра.
fn last_index_fold(s: &str, marker: &str) -> Option<usize> {
    let sb = s.as_bytes();
    let mb = marker.as_bytes();
    if sb.len() < mb.len() {
        return None;
    }
    let mut i = sb.len() - mb.len();
    loop {
        if sb[i..i + mb.len()].eq_ignore_ascii_case(mb) {
            return Some(i);
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

/// Разобрать значение хвоста: base64 (std/url, с паддингом и без) от UTF-8.
fn decode_description(value: &str) -> String {
    let mut value = value.trim();
    if let Some(i) = value.find('&') {
        value = &value[..i];
    }
    if value.is_empty() {
        return String::new();
    }
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for enc in engines {
        let Ok(raw) = enc.decode(value) else { continue };
        let Ok(text) = String::from_utf8(raw) else {
            continue;
        };
        // Управляющие символы (< ' ', кроме \n) в заметки не нужны.
        let cleaned: String = text.chars().filter(|&c| c >= ' ' || c == '\n').collect();
        let mut text = cleaned.trim().to_string();
        while text.len() > MAX_DESCRIPTION_LENGTH {
            text.pop(); // усечение по границе символа (UTF-8)
        }
        return text;
    }
    String::new()
}

/// Отделить от имени хвост «?serverDescription=…»: (имя без хвоста, описание).
fn strip_name_description(name: &str) -> (String, String) {
    let Some(i) = last_index_fold(name, DESCRIPTION_MARKER) else {
        return (name.to_string(), String::new());
    };
    let clean = name[..i].trim_end_matches([' ', '\t']).to_string();
    (
        clean,
        decode_description(&name[i + DESCRIPTION_MARKER.len()..]),
    )
}

/// Отрезать хвост от фрагмента (после «#») сырой ссылки до разбора: имя с
/// длинным описанием не должно упираться в предел длины (порт splitLinkDescription).
pub fn split_link_description(raw: &str) -> (String, String) {
    let Some(hash) = raw.rfind('#') else {
        return (raw.to_string(), String::new());
    };
    let frag = &raw[hash + 1..];
    for marker in [DESCRIPTION_MARKER, DESCRIPTION_MARKER_ENCODED] {
        let Some(i) = last_index_fold(frag, marker) else {
            continue;
        };
        let mut value = frag[i + marker.len()..].to_string();
        if marker == DESCRIPTION_MARKER_ENCODED {
            value = percent_decode(&value);
        }
        return (raw[..hash + 1 + i].to_string(), decode_description(&value));
    }
    (raw.to_string(), String::new())
}

/// Убрать хвост из имени разобранного профиля и положить описание в заметки,
/// если они пусты (порт applyServerDescription).
pub fn apply_server_description(p: &mut Profile, from_link: &str) {
    let (name, from_name) = strip_name_description(&p.name);
    p.name = name;
    let description = if from_link.is_empty() {
        from_name
    } else {
        from_link.to_string()
    };
    if p.notes.is_empty() {
        p.notes = description;
    }
}
