// SPDX-License-Identifier: GPL-3.0-only

//! Порядок route.rules (порт Go `cfgbuild/route.go` routeRules + customrules.go).
//! ЕДИНСТВЕННОЕ место, задающее порядок: sniff → hijack-dns → custom пресета →
//! block/proxy/direct (domain, ip) → процессные → tun-bypass → built-in block.

use crate::error::{Error, Result};
use crate::route::{make_match_rule, RuleSetCollector};
use crate::settings::BuildSettings;
use crate::util::{goos_of, split_lines_skip_sharp, strings_to_value};
use crate::BuildResult;
use lavray_presets::{effective_process_rules, parse_custom_rules, Preset};
use serde_json::{json, Value};

/// Собрать route.rules в порядке sing-box (порт routeRules).
pub fn route_rules(
    preset: &Preset,
    st: &BuildSettings,
    for_test: bool,
    rs: &mut RuleSetCollector,
    res: &mut BuildResult,
) -> Result<Vec<Value>> {
    let mut rules: Vec<Value> = Vec::new();

    if preset.routing.sniffing_mode != 0 {
        rules
            .push(json!({ "action": "sniff", "inbound": ["mixed-in", "tun-in"], "timeout": "3s" }));
    }
    if !for_test {
        rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    }

    if !for_test {
        let preset_rules = parse_custom_rules(&preset.routing.custom_rules).map_err(|e| {
            Error::invalid(
                "preset.routing.custom_rules",
                format!("invalid JSON (expected array or {{\"rules\":[...]}}): {e}"),
            )
        })?;
        rules.extend(preset_rules);
        rules.extend(global_custom_rules(st, res));
    }

    if !for_test {
        let mut add = |list: &[String], is_ip: bool, outbound: &str, rules: &mut Vec<Value>| {
            let mut rule = make_match_rule(list, is_ip, rs);
            if rule.is_empty() {
                return;
            }
            rule.insert("outbound".into(), json!(outbound));
            rules.push(Value::Object(rule));
        };
        add(&preset.routing.block_domain, false, "block", &mut rules);
        add(&preset.routing.proxy_domain, false, "proxy", &mut rules);
        add(&preset.routing.direct_domain, false, "bypass", &mut rules);
        add(&preset.routing.block_ip, true, "block", &mut rules);
        add(&preset.routing.proxy_ip, true, "proxy", &mut rules);
        add(&preset.routing.direct_ip, true, "bypass", &mut rules);
    }

    if !for_test {
        let (prs, _warn) = effective_process_rules(preset, &goos_of(st), st.openwrt);
        for pr in prs {
            rules.push(json!({ "process_name": strings_to_value(&pr.process_names), "outbound": pr.outbound }));
        }
    }

    if st.tun.enabled && !for_test {
        let match_out = if st.tun.whitelist { "proxy" } else { "bypass" };
        let names = split_lines_skip_sharp(&st.tun.bypass_process);
        if !names.is_empty() {
            rules.push(json!({ "process_name": names, "outbound": match_out }));
        }
        let cidrs = split_lines_skip_sharp(&st.tun.bypass_cidr);
        if !cidrs.is_empty() {
            rules.push(json!({ "ip_cidr": cidrs, "outbound": match_out }));
        }
    }

    rules.push(
        json!({ "network": ["udp"], "port": [135, 137, 138, 139, 5353], "outbound": "block" }),
    );
    rules.push(json!({ "ip_cidr": ["224.0.0.0/3", "ff00::/8"], "outbound": "block" }));
    rules.push(json!({ "source_ip_cidr": ["224.0.0.0/3", "ff00::/8"], "outbound": "block" }));

    Ok(rules)
}

/// Правила устаревшей routing.custom_global: негодное значение не ломает запуск —
/// пропускается с замечанием (порт globalCustomRules).
fn global_custom_rules(st: &BuildSettings, res: &mut BuildResult) -> Vec<Value> {
    match parse_custom_rules(&st.custom_route_global) {
        Ok(rules) => rules,
        Err(e) => {
            res.warnings.push(format!(
                "настройка routing.custom_global проигнорирована: {e}"
            ));
            Vec::new()
        }
    }
}
