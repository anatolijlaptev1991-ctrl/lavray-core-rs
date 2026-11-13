// SPDX-License-Identifier: GPL-3.0-only

//! Валидация пресета по SCHEMA §4 — паритет с Go `presets.Preset.Validate`.
//! Ошибки называют путь поля (как в Go).

use crate::limits::{DOMAIN_STRATEGIES, KNOWN_PLATFORMS, KNOWN_PREFIXES, MAX_REVISION};
use crate::types::{Preset, SCHEMA_VERSION};
use thiserror::Error;

/// Ошибка валидации пресета (сообщение содержит путь поля).
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ValidationError(pub String);

type Result<T> = std::result::Result<T, ValidationError>;

fn err(msg: impl Into<String>) -> ValidationError {
    ValidationError(msg.into())
}

impl Preset {
    /// Проверить пресет по SCHEMA §4.
    pub fn validate(&self) -> Result<()> {
        if self.version == 0 || self.version > SCHEMA_VERSION {
            return Err(err(format!(
                "version: схема {} не поддерживается (поддерживается ≤ {SCHEMA_VERSION})",
                self.version
            )));
        }
        if self.id.is_empty() {
            return Err(err("id: пуст"));
        }
        if self.revision > MAX_REVISION {
            return Err(err(format!(
                "revision: {} вне 0…{MAX_REVISION}",
                self.revision
            )));
        }
        if self.name.is_empty() {
            return Err(err("name: пуст"));
        }
        self.routing.validate()?;
        self.dns.validate()?;
        Ok(())
    }
}

impl crate::types::Routing {
    fn validate(&self) -> Result<()> {
        if !matches!(self.def_outbound.as_str(), "proxy" | "direct" | "block") {
            return Err(err(format!(
                "routing.def_outbound: {:?} (допустимо proxy/direct/block)",
                self.def_outbound
            )));
        }
        if !DOMAIN_STRATEGIES.contains(&self.outbound_domain_strategy.as_str()) {
            return Err(err(format!(
                "routing.outbound_domain_strategy: {:?}",
                self.outbound_domain_strategy
            )));
        }
        if !matches!(self.sniffing_mode, 0 | 1) {
            return Err(err(format!(
                "routing.sniffing_mode: {} (допустимо 0/1; режим 2 некора не переносится)",
                self.sniffing_mode
            )));
        }
        for (path, items, is_ip) in [
            ("proxy_domain", &self.proxy_domain, false),
            ("direct_domain", &self.direct_domain, false),
            ("block_domain", &self.block_domain, false),
            ("proxy_ip", &self.proxy_ip, true),
            ("direct_ip", &self.direct_ip, true),
            ("block_ip", &self.block_ip, true),
        ] {
            for s in items {
                validate_list_entry(path, s, is_ip)?;
            }
        }
        for (i, rule) in self.process_rules.iter().enumerate() {
            let path = format!("routing.process_rules[{i}]");
            if !matches!(rule.outbound.as_str(), "proxy" | "direct" | "block") {
                return Err(err(format!("{path}.outbound: {:?}", rule.outbound)));
            }
            for plat in &rule.platforms {
                if !KNOWN_PLATFORMS.contains(&plat.as_str()) {
                    return Err(err(format!(
                        "{path}.platforms: неизвестная платформа {plat:?} (windows/linux/macos/openwrt)"
                    )));
                }
            }
            if rule.process_names.is_empty() {
                return Err(err(format!("{path}.process_names: пуст")));
            }
            for name in &rule.process_names {
                if name.is_empty() || name.contains(['/', '\\']) || name.contains("..") {
                    return Err(err(format!(
                        "{path}.process_names: {name:?} — ожидалось имя процесса без пути"
                    )));
                }
            }
        }
        if !self.custom_rules.is_empty()
            && serde_json::from_str::<serde::de::IgnoredAny>(&self.custom_rules).is_err()
        {
            return Err(err("routing.custom_rules: не является корректным JSON"));
        }
        Ok(())
    }
}

impl crate::types::DnsBlock {
    fn validate(&self) -> Result<()> {
        if !matches!(self.mode.as_str(), "simple" | "advanced") {
            return Err(err(format!("dns.mode: {:?} (simple/advanced)", self.mode)));
        }
        if !DOMAIN_STRATEGIES.contains(&self.remote_query_strategy.as_str()) {
            return Err(err(format!(
                "dns.remote_query_strategy: {:?}",
                self.remote_query_strategy
            )));
        }
        if self.mode == "advanced"
            && serde_json::from_str::<serde::de::IgnoredAny>(&self.advanced_json).is_err()
        {
            return Err(err(
                "dns.advanced_json: mode=advanced требует валидный JSON объекта dns",
            ));
        }
        Ok(())
    }
}

/// Непустая строка, известный префикс, geoip только в ip, geosite только в
/// domain (§4.2 SCHEMA).
fn validate_list_entry(path: &str, s: &str, is_ip: bool) -> Result<()> {
    if s.is_empty() {
        return Err(err(format!("{path}: пустая строка")));
    }
    if s.contains([' ', '\t']) || s.contains('#') {
        return Err(err(format!(
            "{path}: {s:?} — пробелы/«#» недопустимы в элементе списка"
        )));
    }
    let pfx = KNOWN_PREFIXES
        .iter()
        .find(|p| s.starts_with(**p))
        .copied()
        .unwrap_or("");
    if pfx.is_empty() {
        if is_ip && !is_cidr_or_ip(s) {
            return Err(err(format!(
                "{path}: {s:?} — geoip:/CIDR ожидаются в ip-полях"
            )));
        }
        return Ok(());
    }
    match pfx {
        "geoip:" if !is_ip => {
            return Err(err(format!(
                "{path}: {s:?} — geoip допустим только в ip-полях"
            )));
        }
        "geosite:" if is_ip => {
            return Err(err(format!(
                "{path}: {s:?} — geosite допустим только в domain-полях"
            )));
        }
        "domain:" | "full:" | "keyword:" | "regexp:" => {
            if is_ip {
                return Err(err(format!(
                    "{path}: {s:?} — доменные префиксы недопустимы в ip-полях"
                )));
            }
            if s.len() == pfx.len() {
                return Err(err(format!(
                    "{path}: {s:?} — пустое значение после префикса"
                )));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Поверхностная проверка CIDR/IP (полная — на этапе конфигбилдера).
fn is_cidr_or_ip(s: &str) -> bool {
    match s.rfind('/') {
        Some(i) if i > 0 => valid_ipish(&s[..i]),
        Some(_) => false,
        None => valid_ipish(s),
    }
}

fn valid_ipish(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == ':' || ('a'..='f').contains(&c))
}
