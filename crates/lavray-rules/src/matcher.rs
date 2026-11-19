// SPDX-License-Identifier: GPL-3.0-only

//! Матчинг правил (паритет Go `route/rule`): item'ы AND внутри правила,
//! logical — and/or, invert. Контекст CLI-матча — домен или IP
//! (`adapter.InboundContext` с единственным заполненным полем).

use crate::compile::compile_items;
use crate::meta::MatchMeta;
use crate::source::{HeadlessRule, LogicalMode, LogicalRule, PlainRuleSet, RuleSetParseError};

/// Скомпилированный item: описание + предикат.
#[derive(Debug, Clone)]
pub(crate) enum Item {
    /// Условие вне CLI-контекста (port/process/network/…): всегда false.
    Never(String),
    /// Бинарный .srs: домены succinct-set'ом («domain/domain_suffix=<binary>»).
    DomainSet(crate::succinct::SuccinctSet),
    /// Бинарный .srs: IP диапазоны («ip_cidr=<binary>»/«source_ip_cidr=…»).
    IpRanges(Vec<(std::net::IpAddr, std::net::IpAddr)>, String),
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
    fn matches(&self, meta: &MatchMeta) -> bool {
        match (self, meta) {
            (Self::Domain { exact, set, .. }, MatchMeta::Domain(host_raw)) => {
                let host = host_raw.to_lowercase();
                if set.has(crate::strings::reverse_domain(&host).as_bytes()) {
                    return true;
                }
                exact.contains(&host)
            }
            (Self::Keyword { set, .. } | Self::Regex { set, .. }, MatchMeta::Domain(host_raw)) => {
                set.is_match(&host_raw.to_lowercase())
            }
            (Self::IpCidr { nets, .. }, MatchMeta::Ip(ip)) => nets.iter().any(|n| n.contains(ip)),
            (Self::DomainSet(set), MatchMeta::Domain(host_raw)) => {
                let rev = crate::strings::reverse_domain(&host_raw.to_lowercase());
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
        }
    }
}

#[derive(Debug, Clone)]
enum Node {
    Leaf { items: Vec<Item>, invert: bool },
    Logical(LogicalRule, Vec<Node>),
}

/// Скомпилированный rule-set.
#[derive(Debug, Clone, Default)]
pub struct RuleMatcher {
    rules: Vec<Node>,
}

impl RuleMatcher {
    /// Скомпилировать rule-set (regex/ip_cidr — при разборе).
    ///
    /// # Errors
    /// Ошибки компиляции regex (`domain_regex: …`) и CIDR (`ip_cidr: …`).
    pub fn new(set: &PlainRuleSet) -> Result<Self, RuleSetParseError> {
        let mut rules = Vec::with_capacity(set.rules.len());
        for r in &set.rules {
            rules.push(compile(r)?);
        }
        Ok(Self { rules })
    }

    /// Собрать матчер из бинарных .srs-правил (read_ruleset).
    #[must_use]
    pub fn from_binary(rules: Vec<crate::srs::BinaryRule>) -> Self {
        Self {
            rules: rules
                .into_iter()
                .map(|r| Node::Leaf {
                    items: r.items,
                    invert: r.invert,
                })
                .collect(),
        }
    }

    /// Совпавшие правила: (индекс, описание) — печать `match rules.[i]: …`.
    #[must_use]
    pub fn matches(&self, meta: &MatchMeta) -> Vec<(usize, String)> {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, n)| node_matches(n, meta))
            .map(|(i, n)| (i, node_desc(n)))
            .collect()
    }
}

fn node_matches(node: &Node, meta: &MatchMeta) -> bool {
    match node {
        Node::Leaf { items, invert } => {
            let m = items.iter().all(|it| it.matches(meta));
            m != *invert
        }
        Node::Logical(rule, sub) => {
            let m = match rule.mode {
                LogicalMode::And => sub.iter().all(|n| node_matches(n, meta)),
                LogicalMode::Or => sub.iter().any(|n| node_matches(n, meta)),
            };
            m != rule.invert
        }
    }
}

fn node_desc(node: &Node) -> String {
    match node {
        Node::Leaf { items, invert } => {
            let joined = items.iter().map(Item::desc).collect::<Vec<_>>().join(" ");
            if *invert {
                format!("!({joined})")
            } else {
                joined
            }
        }
        Node::Logical(rule, sub) => {
            let op = match rule.mode {
                LogicalMode::And => "&&",
                LogicalMode::Or => "||",
            };
            let joined = sub
                .iter()
                .map(node_desc)
                .collect::<Vec<_>>()
                .join(&format!(" {op} "));
            if rule.invert {
                format!("!({joined})")
            } else {
                joined
            }
        }
    }
}

fn compile(rule: &HeadlessRule) -> Result<Node, RuleSetParseError> {
    match rule {
        HeadlessRule::Empty => Err(RuleSetParseError::MissingConditions),
        HeadlessRule::Logical(l) => {
            let mut sub = Vec::with_capacity(l.rules.len());
            for r in &l.rules {
                sub.push(compile(r)?);
            }
            Ok(Node::Logical((**l).clone(), sub))
        }
        HeadlessRule::Default(d) => Ok(Node::Leaf {
            items: compile_items(d)?,
            invert: d.invert,
        }),
    }
}
