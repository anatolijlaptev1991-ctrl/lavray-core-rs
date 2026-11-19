// SPDX-License-Identifier: GPL-3.0-only

//! Описания item'ов/правил в Go-формате (`String()` у эталона):
//! `domain=www.google.com`, `domain=[a b c...]` (>3 — первые три + «…»),
//! логическое — «a && b» / «a || b», invert — «!(…)».

/// Список значений: 1 — как есть; 2–3 — [a b]; >3 — [a b c...].
pub fn go_list(field: &str, values: &[String]) -> String {
    match values.len() {
        0 => String::new(),
        1 => format!("{field}={}", values[0]),
        2 | 3 => format!("{field}=[{}]", values.join(" ")),
        _ => {
            let head: Vec<&str> = values.iter().take(3).map(String::as_str).collect();
            format!("{field}=[{}...]", head.join(" "))
        }
    }
}

/// Описание DomainItem: domain и domain_suffix в ОДНОЙ строке через пробел.
pub fn domain_item(domains: &[String], suffixes: &[String]) -> String {
    let mut parts = Vec::new();
    if !domains.is_empty() {
        parts.push(go_list("domain", domains));
    }
    if !suffixes.is_empty() {
        parts.push(go_list("domain_suffix", suffixes));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn list_formats() {
        assert_eq!(go_list("domain", &s(&["a.com"])), "domain=a.com");
        assert_eq!(
            go_list("domain", &s(&["a.com", "b.com"])),
            "domain=[a.com b.com]"
        );
        assert_eq!(
            go_list("domain", &s(&["a", "b", "c", "d"])),
            "domain=[a b c...]"
        );
    }

    #[test]
    fn domain_item_combo() {
        assert_eq!(
            domain_item(
                &s(&["accounts.google.com", "www.google.com"]),
                &s(&[".googleapis.com", ".doubleclick.net"])
            ),
            "domain=[accounts.google.com www.google.com] domain_suffix=[.googleapis.com .doubleclick.net]"
        );
        assert_eq!(
            domain_item(&s(&[]), &s(&["gemini"])),
            "domain_suffix=gemini"
        );
    }
}
