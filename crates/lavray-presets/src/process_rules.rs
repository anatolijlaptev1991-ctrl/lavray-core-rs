// SPDX-License-Identifier: GPL-3.0-only

//! Процессные правила набора, применимые на платформе сборки (порт Go
//! `presets/process_rules.go`, SCHEMA §2.1). На OpenWrt-сборке процессные
//! правила опускаются с предупреждением («Не действует на роутере»).

use crate::types::{Preset, ProcessRule};

/// Правила, применимые на платформе `goos` ("windows"/"linux"/"darwin";
/// пустые platforms = все). Возвращает (правила, предупреждения).
#[must_use]
pub fn effective_process_rules(
    p: &Preset,
    goos: &str,
    openwrt: bool,
) -> (Vec<ProcessRule>, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    if openwrt {
        for r in &p.routing.process_rules {
            warnings.push(format!(
                "процессное правило ({}) не действует на роутере — опущено",
                first_or(&r.process_names, &r.outbound)
            ));
        }
        return (out, warnings);
    }
    let plat = match goos {
        "windows" => "windows",
        "darwin" => "macos",
        "linux" => "linux",
        _ => "",
    };
    if plat.is_empty() {
        if !p.routing.process_rules.is_empty() {
            warnings.push(format!(
                "платформа {goos} не поддерживает процессные правила — опущены"
            ));
        }
        return (out, warnings);
    }
    for r in &p.routing.process_rules {
        if r.platforms.is_empty() {
            out.push(r.clone());
            continue;
        }
        if r.platforms.iter().any(|p2| p2 == plat) {
            out.push(r.clone());
        }
    }
    (out, warnings)
}

fn first_or(list: &[String], def: &str) -> String {
    list.first().cloned().unwrap_or_else(|| def.to_string())
}
