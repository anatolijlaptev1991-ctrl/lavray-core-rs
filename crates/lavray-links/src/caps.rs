// SPDX-License-Identifier: GPL-3.0-only

//! Белые списки значений и нормализация (паритет Go `links/util.go` +
//! `network.go`, LNB-17: ошибка импорта вместо ошибки старта ядра).

use crate::util::{LinkError, Result};

/// Транспорты ссылок (xhttp хранится, но cfgbuild сборку отклоняет).
pub const NETWORKS: &[&str] = &["tcp", "http", "ws", "grpc", "httpupgrade", "quic", "xhttp"];

/// Методы shadowsocks (18, паритет Go ssMethods).
pub const SS_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
];

/// security vmess.
pub const VMESS_SECURITIES: &[&str] = &["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"];

/// flow vless.
pub const VLESS_FLOWS: &[&str] = &["xtls-rprx-vision"];

/// Отпечатки uTLS.
pub const UTLS_FPS: &[&str] = &[
    "",
    "chrome",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
];

/// congestion_control tuic.
pub const TUIC_CONGESTIONS: &[&str] = &["", "bbr", "cubic", "new_reno"];

/// udp_relay_mode tuic.
pub const TUIC_RELAY_MODES: &[&str] = &["", "native", "quic"];

/// Синонимы транспорта → имя модели (h2→http, splithttp→xhttp).
pub fn canonical_network(netw: &str) -> String {
    match netw {
        "h2" => "http".into(),
        "splithttp" => "xhttp".into(),
        _ => netw.into(),
    }
}

/// Тримминг элементов ALPN через запятую, пустые отбрасываются.
pub fn normalize_alpn(s: &str) -> String {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

/// security транспортов socks/http: none/0/false/пусто→"", 1/true/tls→"tls".
pub fn normalize_security_none(v: &str) -> Result<String> {
    match v.trim().to_lowercase().as_str() {
        "" | "none" | "0" | "false" => Ok(String::new()),
        "1" | "true" | "tls" => Ok("tls".into()),
        _ => Err(LinkError(format!(
            "неподдерживаемое значение security {v:?} (допустимо: tls/none)"
        ))),
    }
}

/// security vless/trojan/vmess: none/0/false/пусто→"", 1/true/tls→"tls",
/// reality→"reality".
pub fn normalize_security_tls(v: &str) -> Result<String> {
    match v.trim().to_lowercase().as_str() {
        "" | "none" | "0" | "false" => Ok(String::new()),
        "1" | "true" | "tls" => Ok("tls".into()),
        "reality" => Ok("reality".into()),
        _ => Err(LinkError(format!(
            "неподдерживаемое значение security {v:?} (допустимо: tls/reality/none)"
        ))),
    }
}

/// bool-параметр ссылки: строго 1/true→true, иначе false (L2-2 ревью).
pub fn parse_bool_param(v: &str) -> bool {
    matches!(v.trim().to_lowercase().as_str(), "1" | "true")
}

/// Длительность sing-box (hop_interval/heartbeat): число + единица (s/ms/m/h).
pub fn validate_duration(field: &str, s: &str) -> Result<()> {
    if parse_duration_ns(s).is_none() {
        return Err(LinkError(format!(
            "{field}: некорректная длительность {s:?} (пример: 30s)"
        )));
    }
    Ok(())
}

/// Разбор Go-длительности (число с плавающей точкой + единица); значение в нс
/// нужно только для проверки корректности, поэтому возвращаем f64 без каста.
fn parse_duration_ns(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() || s == "0" {
        return Some(0.0);
    }
    let unit_start = s.find(|c: char| c.is_ascii_alphabetic())?;
    let (num, unit) = s.split_at(unit_start);
    let n: f64 = num.parse().ok()?;
    if n < 0.0 {
        return None;
    }
    let mult: f64 = match unit {
        "ns" => 1.0,
        "us" | "µs" => 1e3,
        "ms" => 1e6,
        "s" => 1e9,
        "m" => 60e9,
        "h" => 3600e9,
        _ => return None,
    };
    Some(n * mult)
}

/// mport hy2: только цифры/«:»/«-»/«,», каждая компонента 1..65535 (LNB-15).
pub fn validate_server_ports(s: &str) -> Result<()> {
    if s.is_empty() {
        return Ok(());
    }
    let mut token = String::new();
    let flush = |token: &mut String| -> Result<()> {
        if token.is_empty() {
            return Err(LinkError(format!("mport: пустая компонента в {s:?}")));
        }
        let n: i64 = token
            .parse()
            .map_err(|_| LinkError(format!("mport: порт {token:?} вне диапазона 1–65535")))?;
        if !(1..=65535).contains(&n) {
            return Err(LinkError(format!(
                "mport: порт {token:?} вне диапазона 1–65535"
            )));
        }
        token.clear();
        Ok(())
    };
    for c in s.chars() {
        match c {
            '0'..='9' => token.push(c),
            ':' | '-' | ',' => flush(&mut token)?,
            _ => {
                return Err(LinkError(format!(
                    "mport: недопустимый символ {c:?} в {s:?}"
                )));
            }
        }
    }
    flush(&mut token)
}
