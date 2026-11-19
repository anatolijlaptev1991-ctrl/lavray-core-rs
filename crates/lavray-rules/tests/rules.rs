// SPDX-License-Identifier: GPL-3.0-only

//! Интеграционные тесты lavray-rules против ЗАПИСАННОГО поведения Go-эталона
//! (rust/app-cases/rs-*, recorded 19.11; см. etalon/README.md).

use lavray_rules::{MatchMeta, RuleMatcher, parse_host, parse_source};

fn rs() -> &'static str {
    r#"{
  "version": 3,
  "rules": [
    {"domain": ["accounts.google.com", "www.google.com"]},
    {"domain_suffix": [".googleapis.com", ".doubleclick.net"]},
    {"domain_keyword": ["gemini"]},
    {"domain_regex": ["^ads-[0-9]+\\.example\\.com$"]}
  ]
}"#
}

fn rs_ips() -> &'static str {
    r#"{"version": 3, "rules": [{"ip_cidr": ["10.0.0.0/8", "192.168.1.0/24"]}]}"#
}

fn match_one(json: &str, host: &str) -> Vec<String> {
    let set = parse_source(json).expect("parse");
    let m = RuleMatcher::new(&set).expect("compile");
    m.matches(&parse_host(host))
        .into_iter()
        .map(|(i, d)| format!("match rules.[{i}]: {d}"))
        .collect()
}

#[test]
fn recorded_domain_hit() {
    // rs-match-domain-hit: оба домена в описании, Go-формат списка.
    assert_eq!(
        match_one(rs(), "www.google.com"),
        vec!["match rules.[0]: domain=[accounts.google.com www.google.com]".to_string()]
    );
}

#[test]
fn recorded_suffix_hit() {
    assert_eq!(
        match_one(rs(), "api.googleapis.com"),
        vec!["match rules.[1]: domain_suffix=[.googleapis.com .doubleclick.net]".to_string()]
    );
}

#[test]
fn recorded_keyword_hit() {
    assert_eq!(
        match_one(rs(), "gemini.google.com"),
        vec!["match rules.[2]: domain_keyword=gemini".to_string()]
    );
}

#[test]
fn recorded_regex_hit() {
    assert_eq!(
        match_one(rs(), "ads-42.example.com"),
        vec!["match rules.[3]: domain_regex=^ads-[0-9]+\\.example\\.com$".to_string()]
    );
}

#[test]
fn recorded_miss_empty() {
    // rs-match-miss / rs-match-ip-miss: промах — НИЧЕГО, exit 0.
    assert_eq!(match_one(rs(), "example.org"), Vec::<String>::new());
    assert_eq!(match_one(rs_ips(), "8.8.8.8"), Vec::<String>::new());
}

#[test]
fn recorded_ip_cidr_hit() {
    assert_eq!(
        match_one(rs_ips(), "10.1.2.3"),
        vec!["match rules.[0]: ip_cidr=[10.0.0.0/8 192.168.1.0/24]".to_string()]
    );
    assert_eq!(match_one(rs_ips(), "192.168.1.50").len(), 1);
}

#[test]
fn recorded_ip_against_domain_rules() {
    // rs-match-ip-as-domain-arg: «8.8.8.8» против доменных правил — пусто.
    assert_eq!(match_one(rs(), "8.8.8.8"), Vec::<String>::new());
}

#[test]
fn suffix_semantics_bare_vs_dotted() {
    // bare-суффикс: и ровно, и под-домен; с точкой: только под-.
    let bare = r#"{"version":3,"rules":[{"domain_suffix":["googleapis.com"]}]}"#;
    assert_eq!(match_one(bare, "googleapis.com").len(), 1);
    assert_eq!(match_one(bare, "api.googleapis.com").len(), 1);
    let dotted = r#"{"version":3,"rules":[{"domain_suffix":[".googleapis.com"]}]}"#;
    assert_eq!(match_one(dotted, "googleapis.com"), Vec::<String>::new());
    assert_eq!(match_one(dotted, "api.googleapis.com").len(), 1);
    assert_eq!(match_one(dotted, "xgoogleapis.com"), Vec::<String>::new());
}

#[test]
fn case_sensitivity_recorded() {
    // Хост lowercase; элементы списка — как записаны (recorded: пусто).
    let upper = r#"{"version":3,"rules":[{"domain":["WWW.Google.COM"]}]}"#;
    assert_eq!(match_one(upper, "www.google.com"), Vec::<String>::new());
    let lower = r#"{"version":3,"rules":[{"domain":["www.google.com"]}]}"#;
    assert_eq!(match_one(lower, "WWW.GOOGLE.COM").len(), 1);
    let kw = r#"{"version":3,"rules":[{"domain_keyword":["Gemini"]}]}"#;
    assert_eq!(match_one(kw, "gemini.google.com"), Vec::<String>::new());
}

#[test]
fn invert_and_logical() {
    let inv = r#"{"version":3,"rules":[{"domain":["a.com"],"invert":true}]}"#;
    assert_eq!(match_one(inv, "a.com"), Vec::<String>::new());
    assert_eq!(match_one(inv, "b.com").len(), 1);
    let logical = r#"{"version":3,"rules":[{"type":"logical","mode":"and","rules":[{"domain":["x.com"]},{"domain_keyword":["y"]}]}]}"#;
    assert_eq!(match_one(logical, "x.com").len(), 0);
    let or = r#"{"version":3,"rules":[{"type":"logical","mode":"or","rules":[{"domain":["x.com"]},{"domain_keyword":["y"]}]}]}"#;
    assert_eq!(
        match_one(or, "x.com"),
        vec!["match rules.[0]: domain=x.com || domain_keyword=y".to_string()]
    );
}

#[test]
fn process_never_matches_in_cli_context() {
    // rs-match-process: process_name в CLI-контексте не заполняется.
    let proc = r#"{"version":3,"rules":[{"process_name":["telegram.exe"]}]}"#;
    assert_eq!(match_one(proc, "telegram.exe"), Vec::<String>::new());
}

#[test]
fn unknown_field_go_style() {
    let bad = r#"{"version":3,"rules":[{"user":["1000"]}]}"#;
    let err = parse_source(bad).unwrap_err();
    assert_eq!(err.to_string(), "json: unknown field \"user\"");
    let v1 = r#"{"version":1,"rules":[]}"#;
    assert!(
        parse_source(v1)
            .unwrap_err()
            .to_string()
            .contains("unsupported rule-set version 1")
    );
    let nov = r#"{"rules":[]}"#;
    assert_eq!(
        parse_source(nov).unwrap_err().to_string(),
        "missing rule-set version"
    );
}

#[test]
fn many_values_description() {
    // >3 значений: первые три + «…» (Go strings.Join + "...").
    let many = r#"{"version":3,"rules":[{"domain":["a.com","b.com","c.com","d.com"]}]}"#;
    assert_eq!(
        match_one(many, "a.com"),
        vec!["match rules.[0]: domain=[a.com b.com c.com...]".to_string()]
    );
}

#[test]
fn meta_helpers() {
    assert!(matches!(MatchMeta::domain("x.com"), MatchMeta::Domain(_)));
    assert!(matches!(
        MatchMeta::ip("1.2.3.4".parse().unwrap()),
        MatchMeta::Ip(_)
    ));
}
