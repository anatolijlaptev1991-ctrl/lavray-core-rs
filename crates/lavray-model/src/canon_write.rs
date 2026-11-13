// SPDX-License-Identifier: GPL-3.0-only

//! Вывод канонического дерева (порт Go `model/canonjson.go` writeCanon).
//! Ключи — по порядку байтов UTF-8 (BTreeMap), без HTML-экранирования строк.
//! Вынесено из canonjson.rs ради трещотки размеров.

use crate::canonjson::Canon;

/// Вывести каноническое дерево в строку (без пробелов, ключи сортированы).
pub(crate) fn write_canon(out: &mut String, v: &Canon) {
    match v {
        Canon::Obj(map) => {
            out.push('{');
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                write_canon(out, val);
            }
            out.push('}');
        }
        Canon::Arr(arr) => {
            out.push('[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canon(out, e);
            }
            out.push(']');
        }
        Canon::Str(s) => out.push_str(&serde_json::to_string(s).unwrap_or_default()),
        Canon::Num(n) => out.push_str(n),
        Canon::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Canon::Null => out.push_str("null"),
    }
}
