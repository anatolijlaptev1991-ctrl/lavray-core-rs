// SPDX-License-Identifier: GPL-3.0-only

//! Парсер socks:// (socks4/4a/5) и http:// / https://. Паритет с Go
//! `links/parse.go parseSocksHTTP`.

use crate::util::{
    apply_default_port, frag_name, host_port, parse_url, user_info, LinkError, Result,
};
use lavray_model::{Detail, Profile, ProfileType, SocksHttpDetail};

/// Разобрать socks/http/https ссылку.
pub fn parse(scheme: &str, s: &str) -> Result<Profile> {
    let u = parse_url(s)?;
    let (host, port, present) = host_port(&u)?;
    let (username, password) = user_info(&u);
    let (ptype, proto, default_port) = match scheme {
        "socks" | "socks5" => (ProfileType::Socks, "socks5", 1080),
        "socks4" => (ProfileType::Socks, "socks4", 1080),
        "socks4a" => (ProfileType::Socks, "socks4a", 1080),
        "http" => (ProfileType::Http, "http", 80),
        "https" => (ProfileType::Http, "https", 443),
        _ => return Err(LinkError(format!("неподдерживаемая схема {scheme:?}"))),
    };
    let port = apply_default_port(port, present, default_port)?;
    Ok(Profile {
        r#type: ptype,
        name: frag_name(&u),
        address: host,
        port,
        detail: Some(Detail::SocksHttp(SocksHttpDetail {
            proto: proto.to_string(),
            username,
            password,
        })),
        ..Default::default()
    })
}
