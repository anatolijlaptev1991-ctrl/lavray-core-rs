// SPDX-License-Identifier: GPL-3.0-only

//! Компиляция DefaultRule → item'ы в ПОРЯДКЕ Go `NewDefaultHeadlessRule`
//! (порядок виден в описании правила: `query_type=… network=… domain=… …`).

use crate::matcher::Item;
use crate::source::{DefaultRule, RuleSetParseError};
use crate::strings::{domain_item, go_list};

/// Построить item'ы правила; domain+domain_suffix — один DomainItem.
///
/// # Errors
/// Некорректный `domain_regex`/`ip_cidr`/`source_ip_cidr`.
pub(crate) fn compile_items(d: &DefaultRule) -> Result<Vec<Item>, RuleSetParseError> {
    let mut items = Vec::new();
    if !d.query_type.is_empty() {
        items.push(Item::Never(go_list("query_type", &d.query_type)));
    }
    if !d.network.is_empty() {
        items.push(Item::Never(go_list("network", &d.network)));
    }
    if !d.domain.is_empty() || !d.domain_suffix.is_empty() {
        // bare-суффикс: host==suffix ИЛИ host.ends_with(".suffix");
        // суффикс с точкой: только ends_with (recorded: ".googleapis.com"
        // НЕ матчит ровно googleapis.com; bare — матчит и ровно, и под-).
        let mut exact: std::collections::HashSet<String> = d.domain.iter().cloned().collect();
        let mut dotted: Vec<Vec<u8>> = Vec::new();
        for s in &d.domain_suffix {
            if let Some(stripped) = s.strip_prefix('.') {
                dotted.push(reverse_key(&format!(".{stripped}")));
            } else {
                exact.insert(s.clone());
                dotted.push(reverse_key(&format!(".{s}")));
            }
        }
        dotted.sort();
        dotted.dedup();
        let (leaves, label_bitmap, labels) = crate::srs_build::build_succinct(&dotted);
        let set = crate::succinct::SuccinctSet::from_parts(leaves, label_bitmap, labels)
            .map_err(RuleSetParseError::Other)?;
        items.push(Item::Domain {
            exact,
            set,
            desc: domain_item(&d.domain, &d.domain_suffix),
        });
    }
    if !d.domain_keyword.is_empty() {
        // литеральные подстроки — один RegexSet-проход (экранирование)
        let pats: Vec<String> = d.domain_keyword.iter().map(|k| regex::escape(k)).collect();
        let set = regex::RegexSet::new(&pats)
            .map_err(|e| RuleSetParseError::Other(format!("domain_keyword: {e}")))?;
        items.push(Item::Keyword {
            set,
            desc: go_list("domain_keyword", &d.domain_keyword),
        });
    }
    if !d.domain_regex.is_empty() {
        let set = regex::RegexSet::new(&d.domain_regex).map_err(|e| {
            RuleSetParseError::Other(format!("domain_regex: error parsing regexp: {e}"))
        })?;
        items.push(Item::Regex {
            set,
            desc: go_list("domain_regex", &d.domain_regex),
        });
    }
    if !d.source_ip_cidr.is_empty() {
        items.push(ip_item(true, &d.source_ip_cidr)?);
    }
    if !d.ip_cidr.is_empty() {
        items.push(ip_item(false, &d.ip_cidr)?);
    }
    // Остальные условия CLI-контекстом не заполняются — только описание.
    if !d.source_port.is_empty() {
        items.push(Item::Never(go_list("source_port", &d.source_port)));
    }
    if !d.source_port_range.is_empty() {
        items.push(Item::Never(go_list(
            "source_port_range",
            &d.source_port_range,
        )));
    }
    if !d.port.is_empty() {
        items.push(Item::Never(go_list("port", &d.port)));
    }
    if !d.port_range.is_empty() {
        items.push(Item::Never(go_list("port_range", &d.port_range)));
    }
    if !d.process_name.is_empty() {
        items.push(Item::Never(go_list("process_name", &d.process_name)));
    }
    if !d.process_path.is_empty() {
        items.push(Item::Never(go_list("process_path", &d.process_path)));
    }
    if !d.process_path_regex.is_empty() {
        items.push(Item::Never(go_list(
            "process_path_regex",
            &d.process_path_regex,
        )));
    }
    if !d.package_name.is_empty() {
        items.push(Item::Never(go_list("package_name", &d.package_name)));
    }
    if !d.package_name_regex.is_empty() {
        items.push(Item::Never(go_list(
            "package_name_regex",
            &d.package_name_regex,
        )));
    }
    if !d.network_type.is_empty() {
        items.push(Item::Never(go_list("network_type", &d.network_type)));
    }
    if !d.wifi_ssid.is_empty() {
        items.push(Item::Never(go_list("wifi_ssid", &d.wifi_ssid)));
    }
    if !d.wifi_bssid.is_empty() {
        items.push(Item::Never(go_list("wifi_bssid", &d.wifi_bssid)));
    }
    Ok(items)
}

fn ip_item(source: bool, cidrs: &[String]) -> Result<Item, RuleSetParseError> {
    let field = if source { "source_ip_cidr" } else { "ip_cidr" };
    let mut nets = Vec::with_capacity(cidrs.len());
    for c in cidrs {
        nets.push(c.parse::<ipnet::IpNet>().map_err(|e| {
            RuleSetParseError::Other(format!("{field}: parse CIDR address {c}: {e}"))
        })?);
    }
    Ok(Item::IpCidr {
        nets,
        desc: go_list(field, cidrs),
    })
}

/// Реверс-ключ dot-суффикса для succinct trie: reverse(PREFIX_LABEL+suffix).
fn reverse_key(suffix: &str) -> Vec<u8> {
    let prefix = char::from_u32(0x0d).unwrap_or('?');
    let labeled: String = std::iter::once(prefix).chain(suffix.chars()).collect();
    labeled.chars().rev().collect::<String>().into_bytes()
}
