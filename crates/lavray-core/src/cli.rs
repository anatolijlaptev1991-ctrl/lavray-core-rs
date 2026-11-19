// SPDX-License-Identifier: GPL-3.0-only

//! Субкоманды `check` / `format` (паритет Go boxmain): чтение -c (дефолт
//! config.json), ошибки в FATAL-формате, format без -w пишет в stdout.

use lavray_sbconfig::{CheckStage, FormatOutcome, check, format_config};
use std::path::Path;

pub(crate) use crate::cli_help::RULESET_HELP;

pub(crate) const FATAL: &str = "\x1b[31mFATAL\x1b[0m[0000]";

/// `check [-c <config>]…`; код выхода.
pub fn run_check(args: &[String]) -> i32 {
    let mut paths = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                let Some(p) = args.get(i) else {
                    eprintln!("{FATAL} flag needs an argument: 'c' in -c");
                    return 1;
                };
                paths.push(p.clone());
            }
            other => {
                eprintln!("{FATAL} unknown flag: {other}");
                return 1;
            }
        }
        i += 1;
    }
    if paths.is_empty() {
        paths.push("config.json".to_string());
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    for path in &paths {
        match std::fs::read_to_string(path) {
            Ok(raw) => match check(&raw, path, &cwd) {
                CheckStage::Ok => {}
                CheckStage::Read(t) | CheckStage::Decode(t) | CheckStage::Router(t) => {
                    eprintln!("{FATAL} {t}");
                    return 1;
                }
            },
            Err(e) => {
                eprintln!(
                    "{FATAL} read config at {path}: open {path}: {}",
                    open_os(path, &e)
                );
                return 1;
            }
        }
    }
    0
}

/// `format [-c <config>]… [-w]`; без -w — stdout.
pub fn run_format(args: &[String]) -> i32 {
    let mut paths = Vec::new();
    let mut write = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    paths.push(p.clone());
                }
            }
            "-w" | "--write" => write = true,
            other => {
                eprintln!("{FATAL} unknown flag: {other}");
                return 1;
            }
        }
        i += 1;
    }
    if paths.is_empty() {
        paths.push("config.json".to_string());
    }
    for path in &paths {
        let raw = match std::fs::read_to_string(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{FATAL} read config at {path}: open {path}: {}",
                    open_os(path, &e)
                );
                return 1;
            }
        };
        match format_config(&raw, path) {
            FormatOutcome::Formatted(out) => {
                if write {
                    if let Err(e) = std::fs::write(path, &out) {
                        eprintln!("{FATAL} write config at {path}: {e}");
                        return 1;
                    }
                } else {
                    // Go печатает контент + println → два перевода строки.
                    println!(
                        "{out}
"
                    );
                }
            }
            FormatOutcome::DecodeError(t) => {
                eprintln!("{FATAL} {t}");
                return 1;
            }
        }
    }
    0
}

/// io::Error → английский текст Go (Go не локализует os-сообщения).
pub(crate) fn english_os(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(2) => "The system cannot find the file specified.".into(),
        Some(3) => "The system cannot find the path specified.".into(),
        Some(5) => "Access is denied.".into(),
        Some(13) => "The data is invalid.".into(),
        Some(32) => {
            "The process cannot access the file because it is being used by another process.".into()
        }
        Some(code) => format!("os error {code}"),
        None => e.to_string(),
    }
}

/// Текст os-ошибки открытия: пустой путь — file-not-found (recorded trap-025).
fn open_os(path: &str, e: &std::io::Error) -> String {
    if path.is_empty() {
        "The system cannot find the file specified.".into()
    } else {
        english_os(e)
    }
}

/// Cobra-ошибка неизвестного флага группы rule-set (recorded trap-161..170):
/// Error + usage в stderr + пустая строка + FATAL-строка.
pub(crate) fn ruleset_unknown_flag(flag: &str) {
    let desc = if let Some(short) = flag.strip_prefix('-').and_then(|f| f.chars().next())
        && !flag.starts_with("--")
    {
        format!("unknown shorthand flag: '{short}' in {flag}")
    } else {
        format!("unknown flag: {flag}")
    };
    eprintln!("Error: {desc}");
    eprintln!("{}", crate::cli_help::ruleset_usage_body());
    eprintln!();
    eprintln!("{FATAL} {desc}");
}

/// Первый флаг, не входящий в глобальный набор группы (-c -C -D -h,
/// --config --config-directory --directory --disable-color --help).
pub(crate) fn first_unknown_group_flag(rest: &[String]) -> Option<String> {
    const GLOBAL_SHORT: &[char] = &['c', 'C', 'D', 'h'];
    const GLOBAL_LONG: &[&str] = &[
        "--config",
        "--config-directory",
        "--directory",
        "--disable-color",
        "--help",
    ];
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        if let Some(long) = a.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            let full = format!("--{name}");
            if !GLOBAL_LONG.contains(&full.as_str()) {
                return Some(full);
            }
            if matches!(name, "config" | "config-directory" | "directory") {
                i += 1; // флаг со значением
            }
        } else if let Some(shorts) = a.strip_prefix('-')
            && let Some(first) = shorts.chars().next()
            && !GLOBAL_SHORT.contains(&first)
        {
            return Some(a.to_string());
        }
        i += 1;
    }
    None
}
