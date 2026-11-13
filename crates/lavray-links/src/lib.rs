// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-links
//!
//! Парсинг прокси-ссылок LAVRay — перепись Go `lavray/core/internal/links` на
//! Rust: vmess/vless/trojan/ss/hysteria2/tuic/socks/http. Возвращает
//! [`lavray_model::Profile`] с типоспецифичным `Detail`.

pub mod quic;
pub mod socks_http;
pub mod ss;
pub mod trojan_vless;
pub mod util;
pub mod vmess;

pub use util::{LinkError, Result};

use lavray_model::Profile;

/// Разобрать прокси-ссылку в профиль (паритет Go `links.ParseLink`).
pub fn parse_link(raw: &str) -> Result<Profile> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(LinkError("ссылка пуста".into()));
    }
    if s.len() > util::MAX_LINK_LENGTH {
        return Err(LinkError(format!(
            "ссылка длиннее {} байт",
            util::MAX_LINK_LENGTH
        )));
    }
    let Some(i) = s.find("://") else {
        return Err(LinkError(
            "схема не распознана (ожидается «протокол://…»)".into(),
        ));
    };
    if i == 0 {
        return Err(LinkError(
            "схема не распознана (ожидается «протокол://…»)".into(),
        ));
    }
    let scheme = s[..i].to_lowercase();
    match scheme.as_str() {
        "ss" => ss::parse(s),
        "vmess" => vmess::parse(s),
        "vless" | "trojan" => trojan_vless::parse(&scheme, s),
        "hy2" | "hysteria2" => quic::parse_hysteria2(s),
        "tuic" => quic::parse_tuic(s),
        "socks" | "socks4" | "socks4a" | "socks5" | "http" | "https" => {
            socks_http::parse(&scheme, s)
        }
        "happ" => Err(LinkError(
            "зашифрованная ссылка — это подписка: добавьте её в «Подписки»".into(),
        )),
        _ => Err(LinkError(format!(
            "неподдерживаемая схема {scheme:?} (ss, vmess, vless, trojan, hy2, tuic, socks, http/https)"
        ))),
    }
}
