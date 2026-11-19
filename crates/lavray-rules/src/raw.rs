// SPDX-License-Identifier: GPL-3.0-only

//! Сырые serde-структуры source JSON (union default+logical полей, как
//! Go `option.HeadlessRule`): строгий разбор + unknown-field детекция.

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawRuleSet {
    pub(crate) version: u8,
    #[serde(default)]
    pub(crate) rules: Vec<RawHeadlessRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawHeadlessRule {
    #[serde(rename = "type")]
    pub(crate) kind: Option<String>,
    // logical
    #[serde(default)]
    pub(crate) mode: Option<String>,
    #[serde(default)]
    pub(crate) rules: Option<Vec<RawHeadlessRule>>,
    // default (v3) — Go option.DefaultHeadlessRule
    #[serde(default)]
    pub(crate) query_type: Vec<String>,
    #[serde(default)]
    pub(crate) network: Vec<String>,
    #[serde(default)]
    pub(crate) domain: Vec<String>,
    #[serde(default)]
    pub(crate) domain_suffix: Vec<String>,
    #[serde(default)]
    pub(crate) domain_keyword: Vec<String>,
    #[serde(default)]
    pub(crate) domain_regex: Vec<String>,
    #[serde(default)]
    pub(crate) source_ip_cidr: Vec<String>,
    #[serde(default)]
    pub(crate) ip_cidr: Vec<String>,
    #[serde(default, deserialize_with = "u16_list")]
    pub(crate) source_port: Vec<String>,
    #[serde(default)]
    pub(crate) source_port_range: Vec<String>,
    #[serde(default, deserialize_with = "u16_list")]
    pub(crate) port: Vec<String>,
    #[serde(default)]
    pub(crate) port_range: Vec<String>,
    #[serde(default)]
    pub(crate) process_name: Vec<String>,
    #[serde(default)]
    pub(crate) process_path: Vec<String>,
    #[serde(default)]
    pub(crate) process_path_regex: Vec<String>,
    #[serde(default)]
    pub(crate) package_name: Vec<String>,
    #[serde(default)]
    pub(crate) package_name_regex: Vec<String>,
    #[serde(default)]
    pub(crate) network_type: Vec<String>,
    #[serde(default)]
    pub(crate) wifi_ssid: Vec<String>,
    #[serde(default)]
    pub(crate) wifi_bssid: Vec<String>,
    // Принимаются ради паритета unknown-field (Go v3 имеет их в схеме);
    // в CLI-контексте матча не участвуют.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) network_is_expensive: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) network_is_constrained: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) network_interface_address: serde_json::Value,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) default_interface_address: serde_json::Value,
    #[serde(default)]
    pub(crate) invert: bool,
}

/// Числа (uint16 Go) приходят и строками — приводим к канонической строке.
fn u16_list<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let raw = Vec::<serde_json::Value>::deserialize(d)?;
    let mut out = Vec::with_capacity(raw.len());
    for v in raw {
        match v {
            serde_json::Value::Number(n) => out.push(n.to_string()),
            serde_json::Value::String(s) => out.push(s),
            other => {
                return Err(serde::de::Error::custom(format!(
                    "json: cannot unmarshal {other} into Go value of type uint16"
                )));
            }
        }
    }
    Ok(out)
}
