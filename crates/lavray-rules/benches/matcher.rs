// SPDX-License-Identifier: GPL-3.0-only

//! Бенчи матчера (Criterion): source (exact/suffix/keyword/regex/ip) и
//! бинарный succinct set на 8k rule-set; промахи — худший случай
//! (просматриваются все правила).

use criterion::{Criterion, criterion_group, criterion_main};
use lavray_rules::{MatchMeta, RuleMatcher, parse_host, parse_source};
use std::net::IpAddr;

fn big_source() -> String {
    let mut doms = Vec::new();
    for i in 0..5000 {
        doms.push(format!("site{i}.example{}.com", i % 97));
    }
    let sufs: Vec<String> = (0..3000).map(|i| format!("suffix{i}.org")).collect();
    let kws: Vec<String> = (0..500).map(|i| format!("kw{i}")).collect();
    let regs: Vec<String> = (0..300).map(|i| format!("^re{i}-[a-z]+\\.net$")).collect();
    let ips: Vec<String> = (0..200).map(|i| format!("10.{i}.0.0/16")).collect();
    format!(
        r#"{{"version":3,"rules":[{{"domain":{}}},{{"domain_suffix":{}}},{{"domain_keyword":{}}},{{"domain_regex":{}}},{{"ip_cidr":{}}}]}}"#,
        serde_json::to_string(&doms).unwrap(),
        serde_json::to_string(&sufs).unwrap(),
        serde_json::to_string(&kws).unwrap(),
        serde_json::to_string(&regs).unwrap(),
        serde_json::to_string(&ips).unwrap(),
    )
}

fn matcher() -> RuleMatcher {
    let src = big_source();
    let set = parse_source(&src).expect("parse");
    RuleMatcher::new(&set).expect("compile")
}

fn bench_matcher(c: &mut Criterion) {
    let m = matcher();
    let hit_exact = parse_host("site4999.example51.com");
    let hit_suffix = parse_host("a.suffix2999.org");
    let miss = parse_host("nope.example.org");
    let ip_hit: MatchMeta = MatchMeta::Ip("10.77.7.7".parse::<IpAddr>().unwrap());
    let ip_miss: MatchMeta = MatchMeta::Ip("8.8.8.8".parse::<IpAddr>().unwrap());

    c.bench_function("source/exact_hit_5000", |b| {
        b.iter(|| m.matches(criterion::black_box(&hit_exact)));
    });
    c.bench_function("source/suffix_hit_3000", |b| {
        b.iter(|| m.matches(criterion::black_box(&hit_suffix)));
    });
    c.bench_function("source/miss_all_rules", |b| {
        b.iter(|| m.matches(criterion::black_box(&miss)));
    });
    c.bench_function("source/ip_hit_200nets", |b| {
        b.iter(|| m.matches(criterion::black_box(&ip_hit)));
    });
    c.bench_function("source/ip_miss", |b| {
        b.iter(|| m.matches(criterion::black_box(&ip_miss)));
    });
}

fn bench_binary(c: &mut Criterion) {
    // Тот же rule-set через наш .srs writer — succinct set + диапазоны.
    let src = big_source();
    let set = parse_source(&src).expect("parse");
    let bytes = lavray_rules::srs_write::write_ruleset(&set).expect("write");
    let rules = lavray_rules::srs::read_ruleset(&bytes).expect("read");
    let m = RuleMatcher::from_binary(rules);
    let hit = parse_host("site4999.example51.com");
    let miss = parse_host("nope.example.org");
    c.bench_function("binary/succinct_hit_8k", |b| {
        b.iter(|| m.matches(criterion::black_box(&hit)));
    });
    c.bench_function("binary/succinct_miss_8k", |b| {
        b.iter(|| m.matches(criterion::black_box(&miss)));
    });
    c.bench_function("binary/read_ruleset_8k", |b| {
        b.iter(|| lavray_rules::srs::read_ruleset(criterion::black_box(&bytes)).is_ok());
    });
}

criterion_group!(benches, bench_matcher, bench_binary);
criterion_main!(benches);
