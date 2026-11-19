// SPDX-License-Identifier: GPL-3.0-only

//! `rule-set match <path> <domain|IP> [-f source]` — паритет Go
//! cmd_rule_set_match: вывод `match rules.[N]: …` В STDERR (Go builtin
//! println), exit 0 и при промахе; ошибки — FATAL (exit 1).

use lavray_rules::{RuleMatcher, parse_host, parse_source};

const FATAL: &str = "\x1b[31mFATAL\x1b[0m[0000]";

/// Выполнить подкоманду; возвращает код выхода.
pub fn run_match(args: &[String]) -> i32 {
    let mut path: Option<&str> = None;
    let mut host: Option<&str> = None;
    let mut format = "source".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--format" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    format.clone_from(v);
                }
            }
            other if !other.starts_with('-') => {
                if path.is_none() {
                    path = Some(other);
                } else if host.is_none() {
                    host = Some(other);
                }
            }
            _ => {}
        }
        i += 1;
    }
    let (Some(path), Some(host)) = (path, host) else {
        eprintln!("{FATAL} accepts 2 arg(s), received {}", args.len());
        return 1;
    };
    let matcher = if format == "binary" {
        let raw = match std::fs::read(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{FATAL} read rule-set: open {path}: {e}");
                return 1;
            }
        };
        match lavray_rules::srs::read_ruleset(&raw) {
            Ok(rules) => RuleMatcher::from_binary(rules),
            Err(e) => {
                eprintln!("{FATAL} {e}");
                return 1;
            }
        }
    } else {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{FATAL} read rule-set: open {path}: {e}");
                return 1;
            }
        };
        let set = match parse_source(&content) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{FATAL} {e}");
                return 1;
            }
        };
        match RuleMatcher::new(&set) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("{FATAL} {e}");
                return 1;
            }
        }
    };
    for (idx, desc) in matcher.matches(&parse_host(host)) {
        eprintln!("match rules.[{idx}]: {desc}");
    }
    0
}
