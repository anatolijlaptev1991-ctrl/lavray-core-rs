// SPDX-License-Identifier: GPL-3.0-only

//! Go-стиль текстов ошибок encoding/json (recorded app-cases): сканер
//! типовых синтаксических сбоёв с row/column как у Go, unknown field по
//! порядку следования ключей входа.

/// Синтаксическая ошибка JSON в тексте Go. Покрывает записанные классы
/// (`invalid character 'n' looking for beginning of object key string`);
/// прочее — fallback-текст serde.
#[must_use]
pub fn syntax_error_text(raw: &str, serde_msg: &str) -> String {
    match scan(raw) {
        Some(text) => text,
        None => serde_msg.to_string(),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Expect {
    ObjKey,
    ObjColon,
    ObjValue,
    ObjComma,
    ArrValue,
    ArrComma,
}

fn after_value(e: Expect) -> Expect {
    if e == Expect::ObjValue {
        Expect::ObjComma
    } else {
        Expect::ArrComma
    }
}

/// Компактный сканер: первый байт-нарушитель с координатами Go.
fn scan(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut stack: Vec<Expect> = Vec::new();
    let mut expect = Expect::ArrValue;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
            continue;
        }
        match expect {
            Expect::ObjKey => match b {
                b'"' => {
                    i = skip_string(bytes, i)?;
                    expect = Expect::ObjColon;
                }
                b'}' => {
                    expect = stack.pop()?;
                    i += 1;
                }
                _ => {
                    return Some(invalid_char(
                        b,
                        raw,
                        i,
                        "looking for beginning of object key string",
                    ));
                }
            },
            Expect::ObjColon => {
                if b == b':' {
                    expect = Expect::ObjValue;
                    i += 1;
                } else {
                    return None;
                }
            }
            Expect::ObjValue | Expect::ArrValue => match scan_value(raw, bytes, i, expect) {
                ScanStep::Err(text) => return Some(text),
                ScanStep::Token(next_expect, end) => {
                    expect = next_expect;
                    i = end;
                }
                ScanStep::Fatal => return None,
            },
            Expect::ObjComma => match b {
                b',' => {
                    expect = Expect::ObjKey;
                    i += 1;
                }
                b'}' => {
                    expect = stack.pop()?;
                    i += 1;
                }
                _ => return Some(invalid_char(b, raw, i, "after object key:value pair")),
            },
            Expect::ArrComma => match b {
                b',' => {
                    expect = Expect::ArrValue;
                    i += 1;
                }
                b']' => {
                    expect = stack.pop()?;
                    i += 1;
                }
                _ => return Some(invalid_char(b, raw, i, "after array element")),
            },
        }
    }
    None
}

enum ScanStep {
    /// Ошибка с текстом Go.
    Err(String),
    /// Валидный токен: новое ожидание + позиция за ним.
    Token(Expect, usize),
    /// Неожиданное состояние — отдать fallback serde.
    Fatal,
}

fn scan_value(raw: &str, bytes: &[u8], i: usize, expect: Expect) -> ScanStep {
    let b = bytes[i];
    let after = after_value(expect);
    match b {
        b'"' => match skip_string(bytes, i) {
            Some(end) => ScanStep::Token(after, end),
            None => ScanStep::Fatal,
        },
        b'{' => ScanStep::Token(Expect::ObjKey, i + 1),
        b'[' => ScanStep::Token(Expect::ArrValue, i + 1),
        b']' if expect == Expect::ArrValue => ScanStep::Token(after, i + 1),
        b'-' | b'0'..=b'9' => ScanStep::Token(after, skip_number(bytes, i)),
        _ if raw[i..].starts_with("true")
            || raw[i..].starts_with("false")
            || raw[i..].starts_with("null") =>
        {
            let word = ["true", "false", "null"]
                .iter()
                .find(|w| raw[i..].starts_with(*w))
                .map_or(4, |w| w.len());
            ScanStep::Token(after, i + word)
        }
        _ => {
            let ctx = if expect == Expect::ObjValue {
                "after object key"
            } else {
                "looking for beginning of value"
            };
            ScanStep::Err(invalid_char(b, raw, i, ctx))
        }
    }
}

fn skip_string(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

fn skip_number(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < bytes.len() && matches!(bytes[i], b'-' | b'+' | b'.' | b'0'..=b'9' | b'e' | b'E') {
        i += 1;
    }
    i
}

/// `invalid character 'x' …: row R, column C` — координаты как Go.
fn invalid_char(b: u8, raw: &str, at: usize, ctx: &str) -> String {
    let (row, col) = row_col(raw, at);
    let c = char::from(b);
    format!("invalid character '{c}' {ctx}: row {row}, column {col}")
}

/// Строка/столбец символа на байтовой позиции (Go: column — байты в строке).
#[must_use]
pub fn row_col(raw: &str, at: usize) -> (usize, usize) {
    let mut row = 1usize;
    let mut col = 1usize;
    for (idx, ch) in raw.char_indices() {
        if idx >= at {
            break;
        }
        if ch == '\n' {
            row += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (row, col)
}
