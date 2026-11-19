// SPDX-License-Identifier: GPL-3.0-only

//! Разбор source JSON → `PlainRuleSet` (строгий, unknown fields → ошибка
//! Go-формата). Сырая структура — union всех полей default+logical, как
//! в Go `option.HeadlessRule` (unmarshal по «type»).

use crate::raw::{RawHeadlessRule, RawRuleSet};
use crate::source::{
    DefaultRule, HeadlessRule, LogicalMode, LogicalRule, PlainRuleSet, RuleSetParseError,
};

/// Разобрать rule-set (source JSON v3).
///
/// # Errors
/// Версия ≠ 3 (v1/v2/v4/v5 — отдельные подволнны), неизвестные поля,
/// правила без условий, битый JSON.
pub fn parse_source(raw: &str) -> Result<PlainRuleSet, RuleSetParseError> {
    let raw_set: RawRuleSet = serde_json::from_str(raw).map_err(|e| conv_error(&e))?;
    match raw_set.version {
        3 => {}
        0 => {
            return Err(RuleSetParseError::Version(
                "missing rule-set version".into(),
            ));
        }
        1 | 2 | 4 | 5 => {
            return Err(RuleSetParseError::Version(format!(
                "unsupported rule-set version {} (only 3)",
                raw_set.version
            )));
        }
        n => {
            return Err(RuleSetParseError::Version(format!(
                "unknown rule-set version: {n}"
            )));
        }
    }
    let mut rules = Vec::with_capacity(raw_set.rules.len());
    for r in &raw_set.rules {
        rules.push(convert(r)?);
    }
    Ok(PlainRuleSet { rules })
}

fn convert(raw: &RawHeadlessRule) -> Result<HeadlessRule, RuleSetParseError> {
    match raw.kind.as_deref() {
        None | Some("default") => {
            let def = DefaultRule {
                query_type: raw.query_type.clone(),
                network: raw.network.clone(),
                domain: raw.domain.clone(),
                domain_suffix: raw.domain_suffix.clone(),
                domain_keyword: raw.domain_keyword.clone(),
                domain_regex: raw.domain_regex.clone(),
                source_ip_cidr: raw.source_ip_cidr.clone(),
                ip_cidr: raw.ip_cidr.clone(),
                source_port: raw.source_port.clone(),
                source_port_range: raw.source_port_range.clone(),
                port: raw.port.clone(),
                port_range: raw.port_range.clone(),
                process_name: raw.process_name.clone(),
                process_path: raw.process_path.clone(),
                process_path_regex: raw.process_path_regex.clone(),
                package_name: raw.package_name.clone(),
                package_name_regex: raw.package_name_regex.clone(),
                network_type: raw.network_type.clone(),
                wifi_ssid: raw.wifi_ssid.clone(),
                wifi_bssid: raw.wifi_bssid.clone(),
                invert: raw.invert,
            };
            if !def.has_conditions() {
                return Err(RuleSetParseError::MissingConditions);
            }
            Ok(HeadlessRule::Default(Box::new(def)))
        }
        Some("logical") => {
            let mode = match raw.mode.as_deref() {
                Some("and") => LogicalMode::And,
                Some("or") => LogicalMode::Or,
                other => {
                    return Err(RuleSetParseError::Other(format!(
                        "unknown logical mode: {other:?}"
                    )));
                }
            };
            let mut sub = Vec::new();
            if let Some(raw_rules) = &raw.rules {
                for r in raw_rules {
                    sub.push(convert(r)?);
                }
            }
            if sub.is_empty() {
                return Err(RuleSetParseError::MissingConditions);
            }
            Ok(HeadlessRule::Logical(Box::new(LogicalRule {
                mode,
                rules: sub,
                invert: raw.invert,
            })))
        }
        Some(other) => Err(RuleSetParseError::Other(format!(
            "unknown rule type: {other}"
        ))),
    }
}

/// serde-текст → Go-стиль: `unknown field \`x\`, expected …` → поле,
/// `missing field \`version\`` → `missing rule-set version`.
fn conv_error(e: &serde_json::Error) -> RuleSetParseError {
    let msg = e.to_string();
    if let Some(rest) = msg.strip_prefix("unknown field `") {
        let field = rest.split('`').next().unwrap_or_default();
        return RuleSetParseError::UnknownField(field.to_string());
    }
    if msg.starts_with("missing field `version`") {
        return RuleSetParseError::Version("missing rule-set version".into());
    }
    RuleSetParseError::Other(msg)
}
