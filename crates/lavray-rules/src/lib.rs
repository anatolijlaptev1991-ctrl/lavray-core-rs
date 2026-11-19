// SPDX-License-Identifier: GPL-3.0-only

//! lavray-rules (волна 7f-1): headless rule-set движка — парсинг source
//! JSON (v3), матчинг и описания правил. Паритет с Go sing-box
//! `route/rule` (NewHeadlessRule/DomainItem/IPCIDRItem/…) по recorded
//! behavior эталона 1.14.1-neko.1 (`etalon/README.md`, кейсы `rs-*`).

pub mod compile;
pub mod format;
pub mod matcher;
pub mod meta;
pub mod parse;
pub mod raw;
pub mod source;
pub mod srs;
pub mod srs_build;
pub mod srs_enc;
pub mod srs_items;
pub mod srs_reader;
pub mod srs_write;
pub mod strings;
pub mod succinct;
pub mod succinct_idx;

pub use matcher::RuleMatcher;
pub use meta::MatchMeta;
pub use parse::parse_source;
pub use source::{HeadlessRule, PlainRuleSet, RuleSetParseError};

/// Проверить, что хост — IP-адрес (Go `M.ParseAddr`: валидный IP или домен).
pub fn parse_host(raw: &str) -> MatchMeta {
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        MatchMeta::ip(ip)
    } else {
        MatchMeta::domain(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ip_vs_domain() {
        let MatchMeta::Ip(ip) = parse_host("8.8.8.8") else {
            panic!("IP");
        };
        assert_eq!(ip.to_string(), "8.8.8.8");
        assert!(matches!(parse_host("2001:db8::1"), MatchMeta::Ip(_)));
        assert!(matches!(
            parse_host("gemini.google.com"),
            MatchMeta::Domain(_)
        ));
    }
}
