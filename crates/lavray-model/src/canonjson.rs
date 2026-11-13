// SPDX-License-Identifier: GPL-3.0-only

//! Канонический вид JSON для хэша custom-полей (T-08B, порт Go
//! `model/canonjson.go`). Два документа с одним смыслом дают одну строку:
//! ключи объектов сортированы, пробелов нет, числа сохраняются текстом (без
//! округления до float), HTML не экранируется. Дубли ключей отвергаются.

use crate::canon_write::write_canon;
use std::collections::BTreeMap;

/// Предел вложенности (порт Go maxCanonDepth).
const MAX_CANON_DEPTH: usize = 512;
/// Предел документа: больше custom-JSON не бывает (порт Go MaxCanonBytes).
pub const MAX_CANON_BYTES: usize = 1 << 20;

/// Ошибка канонизации.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonError {
    /// Документ больше MaxCanonBytes.
    #[error("JSON больше {} КиБ", MAX_CANON_BYTES >> 10)]
    TooLarge,
    /// Повторяющийся ключ в объекте.
    #[error("повторяющийся ключ в объекте JSON: {0}")]
    DuplicateKey(String),
    /// Вложенность больше предела.
    #[error("вложенность JSON больше {MAX_CANON_DEPTH}")]
    TooDeep,
    /// Синтаксическая ошибка / лишние данные.
    #[error("{0}")]
    Syntax(String),
}

type Result<T> = std::result::Result<T, CanonError>;

/// Канонический вид документа raw. Пустой/пробельный → "" без ошибки.
pub fn canonical_json(raw: &str) -> Result<String> {
    if raw.len() > MAX_CANON_BYTES {
        return Err(CanonError::TooLarge);
    }
    if raw.trim().is_empty() {
        return Ok(String::new());
    }
    let mut p = Parser {
        b: raw.as_bytes(),
        pos: 0,
    };
    let tree = p.value(0)?;
    p.skip_ws();
    if p.pos != p.b.len() {
        return Err(CanonError::Syntax(
            "после документа JSON есть лишние данные".into(),
        ));
    }
    let mut out = String::with_capacity(raw.len());
    write_canon(&mut out, &tree);
    Ok(out)
}

pub(crate) enum Canon {
    Obj(BTreeMap<String, Canon>),
    Arr(Vec<Canon>),
    Str(String),
    Num(String),
    Bool(bool),
    Null,
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while self.pos < self.b.len() && matches!(self.b[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Result<u8> {
        self.skip_ws();
        self.b
            .get(self.pos)
            .copied()
            .ok_or_else(|| CanonError::Syntax("неожиданный конец JSON".into()))
    }

    fn value(&mut self, depth: usize) -> Result<Canon> {
        if depth > MAX_CANON_DEPTH {
            return Err(CanonError::TooDeep);
        }
        match self.peek()? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Canon::Str(self.string()?)),
            b't' => self.literal("true", Canon::Bool(true)),
            b'f' => self.literal("false", Canon::Bool(false)),
            b'n' => self.literal("null", Canon::Null),
            _ => self.number(),
        }
    }

    fn literal(&mut self, word: &str, v: Canon) -> Result<Canon> {
        if self.b[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(v)
        } else {
            Err(CanonError::Syntax(format!("ожидался {word}")))
        }
    }

    fn object(&mut self, depth: usize) -> Result<Canon> {
        self.pos += 1; // '{'
        let mut map = BTreeMap::new();
        if self.peek()? == b'}' {
            self.pos += 1;
            return Ok(Canon::Obj(map));
        }
        loop {
            if self.peek()? != b'"' {
                return Err(CanonError::Syntax("ключ объекта не строка".into()));
            }
            let key = self.string()?;
            if self.peek()? != b':' {
                return Err(CanonError::Syntax("ожидался ':'".into()));
            }
            self.pos += 1;
            let val = self.value(depth + 1)?;
            if map.insert(key.clone(), val).is_some() {
                return Err(CanonError::DuplicateKey(key));
            }
            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    return Ok(Canon::Obj(map));
                }
                _ => return Err(CanonError::Syntax("ожидался ',' или '}'".into())),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Canon> {
        self.pos += 1; // '['
        let mut arr = Vec::new();
        if self.peek()? == b']' {
            self.pos += 1;
            return Ok(Canon::Arr(arr));
        }
        loop {
            arr.push(self.value(depth + 1)?);
            match self.peek()? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Ok(Canon::Arr(arr));
                }
                _ => return Err(CanonError::Syntax("ожидался ',' или ']'".into())),
            }
        }
    }

    fn string(&mut self) -> Result<String> {
        let start = self.pos;
        self.pos += 1; // opening '"'
        while self.pos < self.b.len() {
            match self.b[self.pos] {
                b'\\' => self.pos += 2,
                b'"' => {
                    let token = &self.b[start..=self.pos];
                    self.pos += 1;
                    let s = std::str::from_utf8(token)
                        .map_err(|_| CanonError::Syntax("некорректный UTF-8 в строке".into()))?;
                    return serde_json::from_str::<String>(s)
                        .map_err(|e| CanonError::Syntax(format!("строка JSON: {e}")));
                }
                _ => self.pos += 1,
            }
        }
        Err(CanonError::Syntax("незакрытая строка".into()))
    }

    fn number(&mut self) -> Result<Canon> {
        let start = self.pos;
        while self.pos < self.b.len()
            && matches!(
                self.b[self.pos],
                b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
            )
        {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.b[start..self.pos])
            .map_err(|_| CanonError::Syntax("некорректное число".into()))?;
        serde_json::from_str::<serde_json::Number>(text)
            .map_err(|_| CanonError::Syntax(format!("некорректное число {text:?}")))?;
        Ok(Canon::Num(text.to_string()))
    }
}
