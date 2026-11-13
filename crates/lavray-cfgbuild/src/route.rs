// SPDX-License-Identifier: GPL-3.0-only

//! route-секция из пресета (порт Go `cfgbuild/route.go`): rule-set коллектор
//! (geosite:/geoip: → локальные .srs), makeMatchRule, buildRoute, cache_file.
//! Порядок правил задаёт route_rules (route_rules.rs) — единый источник.

use crate::error::Result;
use crate::route_rules::route_rules;
use crate::settings::BuildSettings;
use crate::util::{obj, Obj};
use crate::BuildResult;
use lavray_presets::Preset;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Дедуплицированный сбор определений route.rule_set; порядок — порядок встречи.
pub struct RuleSetCollector {
    geo_dir: String,
    order: Vec<String>,
    defs: HashMap<String, Obj>,
}

impl RuleSetCollector {
    /// Каталог поставки .srs (GeoDir; "" → "geo").
    #[must_use]
    pub fn new(st: &BuildSettings) -> Self {
        let geo_dir = st.geo_dir.trim();
        Self {
            geo_dir: if geo_dir.is_empty() {
                "geo".into()
            } else {
                geo_dir.into()
            },
            order: Vec::new(),
            defs: HashMap::new(),
        }
    }

    /// гео-ссылка kind:name → тег "kind-name" + определение local binary rule-set.
    pub fn add(&mut self, kind: &str, name: &str) -> String {
        if name.is_empty() {
            return String::new();
        }
        let tag = format!("{kind}-{name}");
        if self.defs.contains_key(&tag) {
            return tag;
        }
        let mut def = obj();
        def.insert("type".into(), json!("local"));
        def.insert("tag".into(), json!(tag));
        def.insert("format".into(), json!("binary"));
        def.insert(
            "path".into(),
            json!(format!("{}/{kind}/{name}.srs", self.geo_dir)),
        );
        self.defs.insert(tag.clone(), def);
        self.order.push(tag.clone());
        tag
    }

    /// Определения rule_set в порядке встречи (пусто → None).
    #[must_use]
    pub fn list(&self) -> Option<Vec<Value>> {
        if self.order.is_empty() {
            return None;
        }
        Some(
            self.order
                .iter()
                .map(|t| Value::Object(self.defs[t].clone()))
                .collect(),
        )
    }
}

/// Список строк пресета → матч-поля sing-box (порт makeMatchRule). Пустая map —
/// список ничего не дал.
pub fn make_match_rule(list: &[String], is_ip: bool, rs: &mut RuleSetCollector) -> Obj {
    let mut rule = obj();
    let mut rule_set: Vec<Value> = Vec::new();
    let mut ip_cidr: Vec<Value> = Vec::new();
    let mut domain_full: Vec<Value> = Vec::new();
    let mut domain_sub: Vec<Value> = Vec::new();
    let mut domain_kw: Vec<Value> = Vec::new();
    let mut domain_re: Vec<Value> = Vec::new();
    let mut ip_is_private = false;
    let mut seen: Vec<String> = Vec::new();
    let append_rs = |tag: String, rule_set: &mut Vec<Value>, seen: &mut Vec<String>| {
        if tag.is_empty() || seen.contains(&tag) {
            return;
        }
        seen.push(tag.clone());
        rule_set.push(json!(tag));
    };
    for item in list {
        if item.is_empty() {
            continue;
        }
        if is_ip {
            if let Some(rest) = item.strip_prefix("geoip:") {
                if rest == "private" {
                    ip_is_private = true;
                    continue;
                }
                let tag = rs.add("geoip", rest);
                append_rs(tag, &mut rule_set, &mut seen);
            } else {
                ip_cidr.push(json!(item));
            }
            continue;
        }
        if let Some(rest) = item.strip_prefix("geosite:") {
            let tag = rs.add("geosite", rest);
            append_rs(tag, &mut rule_set, &mut seen);
        } else if let Some(rest) = item.strip_prefix("full:") {
            domain_full.push(json!(rest.to_lowercase()));
        } else if let Some(rest) = item.strip_prefix("domain:") {
            domain_sub.push(json!(rest.to_lowercase()));
        } else if let Some(rest) = item.strip_prefix("keyword:") {
            domain_kw.push(json!(rest.to_lowercase()));
        } else if let Some(rest) = item.strip_prefix("regexp:") {
            domain_re.push(json!(rest.to_lowercase()));
        } else {
            domain_sub.push(json!(item.to_lowercase()));
        }
    }
    if !rule_set.is_empty() {
        rule.insert("rule_set".into(), Value::Array(rule_set));
    }
    if is_ip {
        if !ip_cidr.is_empty() {
            rule.insert("ip_cidr".into(), Value::Array(ip_cidr));
        }
        if ip_is_private {
            rule.insert("ip_is_private".into(), json!(true));
        }
        return rule;
    }
    if !domain_full.is_empty() {
        rule.insert("domain".into(), Value::Array(domain_full));
    }
    if !domain_sub.is_empty() {
        rule.insert("domain_suffix".into(), Value::Array(domain_sub));
    }
    if !domain_kw.is_empty() {
        rule.insert("domain_keyword".into(), Value::Array(domain_kw));
    }
    if !domain_re.is_empty() {
        rule.insert("domain_regex".into(), Value::Array(domain_re));
    }
    rule
}

/// route{} конфига (порт buildRoute).
pub fn build_route(
    preset: &Preset,
    st: &BuildSettings,
    res: &mut BuildResult,
    for_test: bool,
    for_export: bool,
    rs: &mut RuleSetCollector,
) -> Result<Obj> {
    let rules = route_rules(preset, st, for_test, rs, res)?;
    let mut route = obj();
    route.insert("rules".into(), Value::Array(rules));
    if let Some(defs) = rs.list() {
        route.insert("rule_set".into(), Value::Array(defs));
    }
    let mut resolver = obj();
    resolver.insert("server".into(), json!("dns-direct"));
    if !preset.routing.outbound_domain_strategy.is_empty() {
        resolver.insert(
            "strategy".into(),
            json!(preset.routing.outbound_domain_strategy),
        );
    }
    route.insert("default_domain_resolver".into(), Value::Object(resolver));
    if st.tun.enabled && !for_export {
        route.insert("auto_detect_interface".into(), json!(true));
    }
    if !for_test {
        route.insert("final".into(), json!(preset.routing.def_outbound));
    }
    Ok(route)
}

/// experimental.cache_file (LNB-36/FR-UI-266): включён всегда в рабочих конфигах.
#[must_use]
pub fn build_experimental(st: &BuildSettings) -> Obj {
    let mut cache = obj();
    cache.insert("enabled".into(), json!(true));
    let p = st.cache_file_path.trim();
    if !p.is_empty() {
        cache.insert("path".into(), json!(p));
    }
    let mut exp = obj();
    exp.insert("cache_file".into(), Value::Object(cache));
    exp
}
