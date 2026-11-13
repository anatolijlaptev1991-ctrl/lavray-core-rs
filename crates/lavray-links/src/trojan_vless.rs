// SPDX-License-Identifier: GPL-3.0-only

//! Парсер trojan:// и vless:// (общий TrojanVLESSBean). Паритет с Go
//! `links/parse.go parseTrojanVLESS`.

use crate::util::{
    apply_default_port, check_field_len, frag_name, host_port, parse_url, query_get, query_pairs,
    user_info, LinkError, Result, MAX_FIELD_LENGTH,
};
use lavray_model::{Detail, Profile, ProfileType, TrojanVlessDetail};

/// Разобрать trojan:// или vless:// ссылку.
pub fn parse(scheme: &str, s: &str) -> Result<Profile> {
    let u = parse_url(s)?;
    let (password, _) = user_info(&u);
    check_field_len("password", &password, MAX_FIELD_LENGTH)?;
    if password.is_empty() {
        return Err(LinkError(format!("{scheme}: не указан пароль/UUID")));
    }
    let (host, port, present) = host_port(&u)?;
    let port = apply_default_port(port, present, 443)?;
    let pairs = query_pairs(&u);
    let flow = query_get(&pairs, "flow").unwrap_or("").to_string();
    let ptype = if scheme == "trojan" {
        ProfileType::Trojan
    } else {
        ProfileType::Vless
    };
    Ok(Profile {
        r#type: ptype,
        name: frag_name(&u),
        address: host,
        port,
        detail: Some(Detail::TrojanVless(TrojanVlessDetail { password, flow })),
        ..Default::default()
    })
}
