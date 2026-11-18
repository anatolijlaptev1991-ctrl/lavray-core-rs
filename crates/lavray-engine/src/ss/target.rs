// SPDX-License-Identifier: GPL-3.0-only

//! Адрес цели SS: байты SOCKS5 (ATYP+addr+port) ↔ TargetAddr. Первый
//! полезный payload туннеля (клиент), вход сервера.

use crate::addr::TargetAddr;

/// Адрес цели → байты SOCKS5 (ATYP + addr + port), первый payload.
#[must_use]
pub fn target_bytes(t: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 255 + 2);
    match t {
        TargetAddr::Domain(d, p) => {
            out.push(0x03);
            let dl = u8::try_from(d.len()).unwrap_or(255);
            out.push(dl);
            out.extend_from_slice(d.as_bytes());
            out.extend_from_slice(&p.to_be_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V4(v), p) => {
            out.push(0x01);
            out.extend_from_slice(&v.octets());
            out.extend_from_slice(&p.to_be_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(v), p) => {
            out.push(0x04);
            out.extend_from_slice(&v.octets());
            out.extend_from_slice(&p.to_be_bytes());
        }
    }
    out
}

/// Байты адреса → цель (для серверной стороны). None — мусор.
#[must_use]
pub fn parse_target(b: &[u8]) -> Option<(TargetAddr, usize)> {
    if b.is_empty() {
        return None;
    }
    match b[0] {
        0x01 if b.len() >= 1 + 4 + 2 => {
            let o: [u8; 4] = b[1..5].try_into().ok()?;
            let ip = std::net::Ipv4Addr::from(o);
            let port = u16::from_be_bytes([b[5], b[6]]);
            Some((TargetAddr::Ip(std::net::IpAddr::V4(ip), port), 7))
        }
        0x03 => {
            let l = *b.get(1)? as usize;
            if b.len() < 2 + l + 2 {
                return None;
            }
            let d = std::str::from_utf8(&b[2..2 + l]).ok()?;
            let port = u16::from_be_bytes([b[2 + l], b[3 + l]]);
            Some((TargetAddr::Domain(d.to_string(), port), 2 + l + 2))
        }
        0x04 if b.len() >= 1 + 16 + 2 => {
            let o: [u8; 16] = b[1..17].try_into().ok()?;
            let ip = std::net::Ipv6Addr::from(o);
            let port = u16::from_be_bytes([b[17], b[18]]);
            Some((TargetAddr::Ip(std::net::IpAddr::V6(ip), port), 19))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_roundtrip() {
        for t in [
            TargetAddr::Domain("example.org".into(), 443),
            TargetAddr::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8080),
            TargetAddr::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 53),
        ] {
            let b = target_bytes(&t);
            let (back, used) = parse_target(&b).expect("parse");
            assert_eq!(back, t);
            assert_eq!(used, b.len());
        }
    }
}
