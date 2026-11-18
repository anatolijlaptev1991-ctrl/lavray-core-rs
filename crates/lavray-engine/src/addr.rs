// SPDX-License-Identifier: GPL-3.0-only

//! Адрес цели соединения (паритет sing-box «address:port» без схемы):
//! домен (как есть, резолв — за outbound-ом) или готовый IP.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Адрес цели: домен или IP + порт.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    /// Доменное имя (регистр сохраняется; матчится регистронезависимо).
    Domain(String, u16),
    /// Готовый IP (без резолва).
    Ip(IpAddr, u16),
}

impl TargetAddr {
    /// Из «host:port»; IPv6 — в скобках. Незакрытый порт — None.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(rest) = s.strip_prefix('[') {
            // [ipv6]:port
            let (host, port) = rest.split_once(']')?;
            if !port.starts_with(':') {
                return None;
            }
            let ip: Ipv6Addr = host.parse().ok()?;
            let port: u16 = port[1..].parse().ok()?;
            return Some(Self::Ip(IpAddr::V6(ip), port));
        }
        let (host, port) = s.split_once(':')?;
        let port: u16 = port.parse().ok()?;
        if host.parse::<Ipv4Addr>().is_ok() {
            return Some(Self::Ip(IpAddr::V4(host.parse::<Ipv4Addr>().ok()?), port));
        }
        if host.contains(':') {
            return None; // голый IPv6 без скобок и порта
        }
        if host.is_empty() || port == 0 {
            return None;
        }
        Some(Self::Domain(host.to_string(), port))
    }

    /// Хост для connect: домен — как есть (резолв за std), IP — строкой.
    #[must_use]
    pub fn host_string(&self) -> String {
        match self {
            Self::Domain(h, _) => h.clone(),
            Self::Ip(ip, _) => ip.to_string(),
        }
    }

    /// Порт.
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, p) | Self::Ip(_, p) => *p,
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(h, p) => write!(f, "{h}:{p}"),
            Self::Ip(std::net::IpAddr::V4(v), p) => write!(f, "{v}:{p}"),
            Self::Ip(std::net::IpAddr::V6(v), p) => write!(f, "[{v}]:{p}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain_ipv4_ipv6() {
        assert_eq!(
            TargetAddr::parse("example.org:443"),
            Some(TargetAddr::Domain("example.org".into(), 443))
        );
        assert_eq!(
            TargetAddr::parse("127.0.0.1:8080"),
            Some(TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))
        );
        assert_eq!(
            TargetAddr::parse("[::1]:53"),
            Some(TargetAddr::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 53))
        );
        assert_eq!(TargetAddr::parse("nohost"), None);
        assert_eq!(TargetAddr::parse("a:b"), None); // не число-порт
        assert_eq!(TargetAddr::parse("a:0"), None);
    }

    #[test]
    fn display_roundtrip() {
        for s in ["example.org:443", "10.0.0.1:1", "[2001:db8::1]:80"] {
            let a = TargetAddr::parse(s).expect(s);
            assert_eq!(a.to_string(), s);
        }
    }
}
