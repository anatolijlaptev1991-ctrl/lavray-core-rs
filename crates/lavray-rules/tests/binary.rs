// SPDX-License-Identifier: GPL-3.0-only

//! Бинарные .srs: паритет с Go-эталоном (compiled из того же JSON).

use lavray_rules::{RuleMatcher, parse_host};

// ---- Бинарные .srs (compiled эталоном из того же JSON, magic SRS v2) ----

const SITE_SRS: &[u8] = include_bytes!("../tests/srs/site.srs");
const IP_SRS: &[u8] = include_bytes!("../tests/srs/ip.srs");

fn binary_matches(raw: &[u8], host: &str) -> Vec<String> {
    let rules = lavray_rules::srs::read_ruleset(raw).expect("read");
    let m = RuleMatcher::from_binary(rules);
    m.matches(&parse_host(host))
        .into_iter()
        .map(|(i, d)| format!("match rules.[{i}]: {d}"))
        .collect()
}

#[test]
fn binary_domain_match_paritet() {
    // recorded: эталон печатает domain/domain_suffix=<binary> на hit,
    // пусто на промах; под-домены bare-суффиксов матчатся.
    assert_eq!(
        binary_matches(SITE_SRS, "example.com"),
        vec!["match rules.[0]: domain/domain_suffix=<binary>".to_string()]
    );
    assert_eq!(binary_matches(SITE_SRS, "sub.example.com").len(), 1);
    assert_eq!(
        binary_matches(SITE_SRS, "xexample.com"),
        Vec::<String>::new()
    );
    assert_eq!(binary_matches(SITE_SRS, "nope.org"), Vec::<String>::new());
}

#[test]
fn binary_ip_ranges_paritet() {
    assert_eq!(
        binary_matches(IP_SRS, "10.1.2.3"),
        vec!["match rules.[0]: ip_cidr=<binary>".to_string()]
    );
    assert_eq!(binary_matches(IP_SRS, "10.255.0.1").len(), 1);
    assert_eq!(binary_matches(IP_SRS, "8.8.8.8"), Vec::<String>::new());
}

#[test]
fn binary_rejects_garbage() {
    assert!(lavray_rules::srs::read_ruleset(b"nope").is_err());
    assert!(lavray_rules::srs::read_ruleset(b"SRS\x09junk").is_err());
}
