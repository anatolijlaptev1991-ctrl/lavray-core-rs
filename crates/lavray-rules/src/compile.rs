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
        let mut exact = d.domain.clone();
        let mut dotted: Vec<String> = Vec::new();
        for s in &d.domain_suffix {
            if let Some(stripped) = s.strip_prefix('.') {
                dotted.push(format!(".{stripped}"));
            } else {
                exact.push(s.clone());
                dotted.push(format!(".{s}"));
            }
        }
        items.push(Item::Domain {
            exact,
            dotted,
            desc: domain_item(&d.domain, &d.domain_suffix),
        });
    }
    if !d.domain_keyword.is_empty() {
        items.push(Item::Keyword {
            list: d.domain_keyword.clone(),
            desc: go_list("domain_keyword", &d.domain_keyword),
        });
    }
    if !d.domain_regex.is_empty() {
        let mut list = Vec::with_capacity(d.domain_regex.len());
        for r in &d.domain_regex {
            list.push(regex::Regex::new(r).map_err(|e| {
                RuleSetParseError::Other(format!("domain_regex: error parsing regexp: {e}"))
            })?);
        }
        items.push(Item::Regex {
            list,
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
