// SPDX-License-Identifier: GPL-3.0-only

//! Контекст матча: домен или IP (как `M.ParseAddr` + InboundContext CLI).

use std::net::IpAddr;

/// Контекст матча: домен или IP (как `M.ParseAddr` в cmd_rule_set_match).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchMeta {
    Domain(String),
    Ip(IpAddr),
}

impl MatchMeta {
    /// Контекст-домен.
    #[must_use]
    pub fn domain(d: &str) -> Self {
        Self::Domain(d.to_string())
    }
    /// Контекст-IP.
    #[must_use]
    pub fn ip(a: IpAddr) -> Self {
        Self::Ip(a)
    }
}
