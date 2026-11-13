// SPDX-License-Identifier: GPL-3.0-only

//! legacy-строка адреса DNS → типизированный сервер sing-box 1.14 (порт Go
//! `cfgbuild/dns.go` makeDnsServer). Вынесено из dns.rs ради трещотки размеров.

use crate::error::{Error, Result};
use crate::util::{obj, Obj};
use serde_json::json;

/// Формы: "local", "fakeip", "[udp://|tls://|https://|h3://|quic://|tcp://|
/// dhcp://]хост[:порт][/path]" (для https/h3 путь сохраняется).
pub fn make_dns_server(tag: &str, address: &str, detour: &str, use_resolver: bool) -> Result<Obj> {
    let address = address.trim();
    let address = if address.is_empty() { "local" } else { address };
    let mut o = obj();
    o.insert("tag".into(), json!(tag));
    if address == "local" {
        o.insert("type".into(), json!("local"));
        if !detour.is_empty() {
            o.insert("detour".into(), json!(detour));
        }
        return Ok(o);
    }
    if address == "fakeip" {
        o.insert("type".into(), json!("fakeip"));
        o.insert("inet4_range".into(), json!("198.18.0.0/15"));
        o.insert("inet6_range".into(), json!("fc00::/18"));
        return Ok(o);
    }

    let mut typ = "udp";
    let mut server = address.to_string();
    if let Some(i) = server.find("://") {
        if i > 0 {
            let scheme = server[..i].to_lowercase();
            server = server[i + 3..].to_string();
            typ = match scheme.as_str() {
                "tls" => "tls",
                "https" => "https",
                "h3" => "h3",
                "quic" => "quic",
                "tcp" => "tcp",
                "dhcp" => "dhcp",
                _ => "udp",
            };
        }
    }
    if let Some(slash) = server.find('/') {
        if typ == "https" || typ == "h3" {
            o.insert("path".into(), json!(&server[slash..]));
        }
        server = server[..slash].to_string();
    }
    let mut server_port = 0i64;
    if let Some(rest) = server.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let after = &rest[close + 1..];
            if let Some(p) = after.strip_prefix(':') {
                server_port = p.parse().unwrap_or(0);
            }
            server = rest[..close].to_string();
        }
    } else if let Some(colon) = server.rfind(':') {
        if colon > 0 {
            if let Ok(v) = server[colon + 1..].parse::<i64>() {
                if v > 0 {
                    server_port = v;
                    server = server[..colon].to_string();
                }
            }
        }
    }
    if server.is_empty() {
        return Err(Error::invalid(
            "preset.dns",
            format!("dns server address {address:?}: empty host"),
        ));
    }
    o.insert("type".into(), json!(typ));
    o.insert("server".into(), json!(server));
    if server_port > 0 {
        o.insert("server_port".into(), json!(server_port));
    }
    if !detour.is_empty() && detour != "direct" {
        o.insert("detour".into(), json!(detour));
    }
    if use_resolver {
        o.insert("domain_resolver".into(), json!("dns-local"));
    }
    Ok(o)
}
