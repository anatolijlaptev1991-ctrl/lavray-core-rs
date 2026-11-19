// SPDX-License-Identifier: GPL-3.0-only

//! `rule-set match <path> <domain|IP> [-f source]` — паритет Go
//! cmd_rule_set_match: вывод `match rules.[N]: …` В STDERR (Go builtin
//! println), exit 0 и при промахе; ошибки — FATAL (exit 1).

use lavray_rules::{RuleMatcher, parse_host, parse_source};

const FATAL: &str = "\x1b[31mFATAL\x1b[0m[0000]";

/// `rule-set format <path>`: pretty-JSON c нормализацией Go Listable
/// (синглтоны — скаляры), stdout, двойной перевод строки (Go println).
pub fn run_format(args: &[String]) -> i32 {
    let Some(path) = args.first() else {
        eprintln!("{FATAL} accepts 1 arg(s), received 0");
        return 1;
    };
    let read_err = |e: std::io::Error| {
        let os = if path.is_empty() {
            "The system cannot find the file specified.".to_string()
        } else {
            crate::cli::english_os(&e)
        };
        eprintln!("{FATAL} open {path}: {os}");
        1
    };
    match std::fs::read_to_string(path) {
        Ok(raw) => match lavray_rules::format::format_source(&raw) {
            Ok(out) => {
                println!("{out}\n");
                0
            }
            Err(e) => {
                eprintln!("{FATAL} {e}");
                1
            }
        },
        Err(e) => read_err(e),
    }
}

/// `rule-set compile <src> [-o out]`: source JSON → бинарный .srs v2.
pub fn run_compile(args: &[String]) -> i32 {
    let mut path: Option<&str> = None;
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    out = Some(v.clone());
                }
            }
            other if !other.starts_with('-') => path = Some(other),
            _ => {}
        }
        i += 1;
    }
    let Some(path) = path else {
        eprintln!("{FATAL} accepts 1 arg(s), received 0");
        return 1;
    };
    let out = out.unwrap_or_else(|| {
        path.strip_suffix(".json")
            .map_or_else(|| format!("{path}.srs"), |stem| format!("{stem}.srs"))
    });
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{FATAL} open {path}: {}", crate::cli::english_os(&e));
            return 1;
        }
    };
    let set = match lavray_rules::parse_source(&raw) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{FATAL} {e}");
            return 1;
        }
    };
    match lavray_rules::srs_write::write_ruleset(&set) {
        Ok(bytes) => match std::fs::write(&out, bytes) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("{FATAL} open {out}: {}", open_os(&out, &e));
                1
            }
        },
        Err(e) => {
            eprintln!("{FATAL} {e}");
            1
        }
    }
}

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
                eprintln!("{FATAL} read rule-set: open {path}: {}", open_os(path, &e));
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
                eprintln!("{FATAL} read rule-set: open {path}: {}", open_os(path, &e));
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

/// Текст os-ошибки открытия: пустой путь — file-not-found (recorded trap-025).
fn open_os(path: &str, e: &std::io::Error) -> String {
    if path.is_empty() {
        "The system cannot find the file specified.".into()
    } else {
        crate::cli::english_os(e)
    }
}
