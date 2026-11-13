// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-links
//!
//! Парсинг прокси-ссылок LAVRay — перепись Go `lavray/core/internal/links` на
//! Rust: vmess/vless/trojan/ss/hysteria2/tuic/socks/http. Возвращает
//! [`lavray_model::Profile`] с типоспецифичным `Detail`.

pub mod caps;
pub mod description;
pub mod neko;
mod neko_bean;
mod neko_detail;
mod neko_detail_quic;
pub mod quic;
pub mod socks_http;
pub mod ss;
pub mod stream;
pub mod trojan_vless;
pub mod util;
pub mod vmess;
mod vmess_json;

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
    // 0.2.1: хвост «?serverDescription=<base64>» в имени — служебный (P2-11).
    let (s, description) = description::split_link_description(s);
    let mut p = parse_scheme(&scheme, &s)?;
    description::apply_server_description(&mut p, &description);
    Ok(p)
}

fn parse_scheme(scheme: &str, s: &str) -> Result<Profile> {
    match scheme {
        "ss" => ss::parse(s),
        "vmess" => vmess::parse(s),
        "vless" | "trojan" => trojan_vless::parse(scheme, s),
        "hy2" | "hysteria2" => quic::parse_hysteria2(s),
        "tuic" => quic::parse_tuic(s),
        "socks" | "socks4" | "socks4a" | "socks5" | "http" | "https" => {
            socks_http::parse(scheme, s)
        }
        "nekoray" => neko::parse_neko_link(s),
        "happ" => Err(LinkError(
            "зашифрованная ссылка — это подписка: добавьте её в «Подписки»".into(),
        )),
        _ => Err(LinkError(format!(
            "неподдерживаемая схема {scheme:?} (ss, vmess, vless, trojan, hy2, tuic, socks, http/https, nekoray)"
        ))),
    }
}
