// SPDX-License-Identifier: GPL-3.0-only

//! Скомпилированные item'ы правил + их описания (Go `String()`).

use crate::meta::MatchMeta;
use crate::strings::reverse_domain;

#[derive(Debug, Clone)]
pub(crate) enum Item {
    /// Условие вне CLI-контекста (port/process/network/…): всегда false.
    Never(String),
    /// Бинарный .srs: домены succinct-set'ом («domain/domain_suffix=<binary>»).
    DomainSet(crate::succinct::SuccinctSet),
    /// Бинарный .srs: IP диапазоны («ip_cidr=<binary>»/«source_ip_cidr=…»).
    IpRanges(Vec<(std::net::IpAddr, std::net::IpAddr)>, String),
    /// Бинарный .srs: AdGuard-матчер.
    AdGuard(crate::adguard::AdGuardMatcher),
    /// Бинарный .srs: логическое правило (mode and/or над подправилами).
    Logical {
        /// true = «or».
        mode_or: bool,
        sub: Vec<crate::srs::BinaryRule>,
        invert: bool,
    },
    Domain {
        exact: std::collections::HashSet<String>,
        /// dot-суффиксы — succinct trie (O(len(host)), как binary .srs).
        set: crate::succinct::SuccinctSet,
        desc: String,
    },
    Keyword {
        set: regex::RegexSet,
        desc: String,
    },
    Regex {
        set: regex::RegexSet,
        desc: String,
    },
    IpCidr {
        nets: Vec<ipnet::IpNet>,
        desc: String,
    },
}

impl Item {
    pub(crate) fn matches(&self, meta: &MatchMeta) -> bool {
        match (self, meta) {
            (Self::Domain { exact, set, .. }, MatchMeta::Domain(host_raw)) => {
                let host = host_raw.to_lowercase();
                if set.has(reverse_domain(&host).as_bytes()) {
                    return true;
                }
                exact.contains(&host)
            }
            (Self::Keyword { set, .. } | Self::Regex { set, .. }, MatchMeta::Domain(host_raw)) => {
                set.is_match(&host_raw.to_lowercase())
            }
            (Self::IpCidr { nets, .. }, MatchMeta::Ip(ip)) => nets.iter().any(|n| n.contains(ip)),
            (Self::DomainSet(set), MatchMeta::Domain(host_raw)) => {
                let rev = reverse_domain(&host_raw.to_lowercase());
                set.has(rev.as_bytes())
            }
            (Self::IpRanges(ranges, _), MatchMeta::Ip(ip)) => {
                // диапазоны отсортированы по from: идём вниз от последнего ≤ ip
                let start = ranges.partition_point(|(from, _)| *from <= *ip);
                ranges[..start]
                    .iter()
                    .rev()
                    .any(|(from, to)| crate::srs::ip_in_range(*ip, *from, *to))
            }
            (Self::AdGuard(m), MatchMeta::Domain(host_raw)) => m.is_match(&host_raw.to_lowercase()),
            (
                Self::Logical {
                    mode_or,
                    sub,
                    invert: self_invert,
                },
                meta,
            ) => {
                let m = if *mode_or {
                    sub.iter()
                        .any(|r| crate::srs::binary_rule_matches(&r.items, r.invert, meta))
                } else {
                    sub.iter()
                        .all(|r| crate::srs::binary_rule_matches(&r.items, r.invert, meta))
                };
                m != *self_invert
            }
            // доменные item'ы не матчат IP-контекст и наоборот (recorded:
            // «8.8.8.8» против доменных правил — пусто).
            _ => false,
        }
    }
    fn desc(&self) -> String {
        match self {
            Self::Never(d)
            | Self::Domain { desc: d, .. }
            | Self::Keyword { desc: d, .. }
            | Self::Regex { desc: d, .. }
            | Self::IpCidr { desc: d, .. }
            | Self::IpRanges(_, d) => d.clone(),
            Self::DomainSet(_) => "domain/domain_suffix=<binary>".into(),
            Self::AdGuard(_) => "!adguard_domain_rules=<binary>".into(),
            Self::Logical {
                mode_or,
                sub,
                invert: _,
            } => {
                // Go: строки описаний подправил через " && "/" || "
                let op = if *mode_or { " || " } else { " && " };
                sub.iter()
                    .map(|r| items_desc(&r.items))
                    .collect::<Vec<_>>()
                    .join(op)
            }
        }
    }
}

/// Строковые описания item'ов правила через пробел (Go abstractDefaultRule).
pub(crate) fn items_desc(items: &[Item]) -> String {
    items.iter().map(Item::desc).collect::<Vec<_>>().join(" ")
}
