// SPDX-License-Identifier: GPL-3.0-only

//! Source JSON headless rule-set (паритет Go `option.PlainRuleSetCompat`,
//! version 3). Строгий разбор: неизвестные поля — ошибка в Go-формате
//! `json: unknown field "x"` (recorded behavior traps).

use std::fmt;

/// Ошибка разбора rule-set. Тексты — к Go-эталону, где зафиксированы кейсами.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSetParseError {
    /// `missing rule-set version` / `unknown rule-set version: N`.
    Version(String),
    /// `json: unknown field "x"` — конверсия из serde-текста.
    UnknownField(String),
    /// `missing conditions` — правило без полей.
    MissingConditions,
    /// Прочее (битый JSON, invalid regex, …) — текст Go-стиля.
    Other(String),
}

impl fmt::Display for RuleSetParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version(s) | Self::Other(s) => write!(f, "{s}"),
            Self::UnknownField(s) => write!(f, "json: unknown field \"{s}\""),
            Self::MissingConditions => write!(f, "missing conditions"),
        }
    }
}

impl std::error::Error for RuleSetParseError {}

/// Правило: default (набор условий) или logical (and/or над подправилами).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HeadlessRule {
    #[default]
    Empty,
    Default(Box<DefaultRule>),
    Logical(Box<LogicalRule>),
}

/// Default-правило: поля из Go `option.DefaultHeadlessRule` (v3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DefaultRule {
    pub query_type: Vec<String>,
    pub network: Vec<String>,
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub source_ip_cidr: Vec<String>,
    pub ip_cidr: Vec<String>,
    pub source_port: Vec<String>,
    pub source_port_range: Vec<String>,
    pub port: Vec<String>,
    pub port_range: Vec<String>,
    pub process_name: Vec<String>,
    pub process_path: Vec<String>,
    pub process_path_regex: Vec<String>,
    pub package_name: Vec<String>,
    pub package_name_regex: Vec<String>,
    pub network_type: Vec<String>,
    pub wifi_ssid: Vec<String>,
    pub wifi_bssid: Vec<String>,
    pub invert: bool,
}

/// Logical-правило: mode and/or над подправилами (+invert).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalRule {
    pub mode: LogicalMode,
    pub rules: Vec<HeadlessRule>,
    pub invert: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalMode {
    And,
    Or,
}

/// Разобранный rule-set (source v3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlainRuleSet {
    pub rules: Vec<HeadlessRule>,
}

impl DefaultRule {
    /// Есть ли хоть одно условие (Go `IsValid` — не дефолт кроме invert).
    pub fn has_conditions(&self) -> bool {
        let DefaultRule {
            query_type,
            network,
            domain,
            domain_suffix,
            domain_keyword,
            domain_regex,
            source_ip_cidr,
            ip_cidr,
            source_port,
            source_port_range,
            port,
            port_range,
            process_name,
            process_path,
            process_path_regex,
            package_name,
            package_name_regex,
            network_type,
            wifi_ssid,
            wifi_bssid,
            invert: _,
        } = self;
        [
            query_type,
            network,
            domain,
            domain_suffix,
            domain_keyword,
            domain_regex,
            source_ip_cidr,
            ip_cidr,
            source_port,
            source_port_range,
            port,
            port_range,
            process_name,
            process_path,
            process_path_regex,
            package_name,
            package_name_regex,
            network_type,
            wifi_ssid,
            wifi_bssid,
        ]
        .iter()
        .any(|v| !v.is_empty())
    }
}
