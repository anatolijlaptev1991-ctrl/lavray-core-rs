// SPDX-License-Identifier: GPL-3.0-only

//! Перевод строки server_ports профиля в формат sing-box 1.14 (порт Go
//! `cfgbuild/hy2ports.go`): список диапазонов «a:b». Одиночный порт p → «p:p»,
//! «a-b»/«a:b» → «a:b», запятая разделяет. Мусор → InvalidArgument.

use crate::error::{Error, Result};

/// Привести строку портов к списку диапазонов «a:b». Пустая строка → пусто.
pub fn hysteria2_server_ports(s: &str) -> Result<Vec<String>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for raw in s.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            return Err(Error::invalid(
                "detail.server_ports",
                format!("hysteria2: пустой элемент в списке портов {s:?}"),
            ));
        }
        let (lo, hi) = parse_port_range(item).map_err(|e| {
            Error::invalid(
                "detail.server_ports",
                format!("hysteria2: неверный диапазон портов {item:?} (ожидается порт, a:b или a-b, 1–65535): {e}"),
            )
        })?;
        out.push(format!("{lo}:{hi}"));
    }
    Ok(out)
}

/// Разобрать «p», «a:b» или «a-b» в пару границ [lo, hi].
fn parse_port_range(item: &str) -> std::result::Result<(u32, u32), String> {
    let sep = item.find([':', '-']);
    let Some(sep) = sep else {
        let lo = parse_port_number(item)?;
        return Ok((lo, lo));
    };
    let lo = parse_port_number(&item[..sep])?;
    let hi = parse_port_number(&item[sep + 1..])?;
    if lo > hi {
        return Err("начало диапазона больше конца".into());
    }
    Ok((lo, hi))
}

/// Десятичный порт 1..65535 (без знака и пробелов).
fn parse_port_number(s: &str) -> std::result::Result<u32, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("пустая граница".into());
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("недопустимый символ в {s:?}"));
    }
    let n: u32 = s
        .parse()
        .map_err(|_| format!("порт {s:?} вне диапазона 1–65535"))?;
    if !(1..=65535).contains(&n) {
        return Err(format!("порт {s:?} вне диапазона 1–65535"));
    }
    Ok(n)
}
