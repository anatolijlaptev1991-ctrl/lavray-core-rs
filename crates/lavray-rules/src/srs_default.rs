// SPDX-License-Identifier: GPL-3.0-only

//! Чтение default-правила .srs: item'ы в порядке Go writeDefaultRule.

use crate::items::Item;
use crate::source::RuleSetParseError;
use crate::srs::BinaryRule;
use crate::srs_items::{
    ITEM_ADGUARD_DOMAIN, ITEM_DEFAULT_IFACE_ADDR, ITEM_DOMAIN, ITEM_DOMAIN_KEYWORD,
    ITEM_DOMAIN_REGEX, ITEM_FINAL, ITEM_IP_CIDR, ITEM_NETWORK_IFACE_ADDR, ITEM_NETWORK_TYPE,
    ITEM_SOURCE_IP_CIDR, read_ipset, read_prefix, read_string_item, read_strings, read_succinct,
    read_u16_item,
};
use crate::srs_reader::Reader;

pub(crate) fn read_default(r: &mut Reader) -> Result<BinaryRule, RuleSetParseError> {
    let mut items = Vec::new();
    loop {
        let item_type = r.u8()?;
        if let Some(item) = read_string_item(r, item_type)? {
            items.push(item);
            continue;
        }
        if let Some(item) = read_u16_item(r, item_type)? {
            items.push(item);
            continue;
        }
        match item_type {
            ITEM_FINAL => {
                let invert = r.u8()? != 0;
                return Ok(BinaryRule { items, invert });
            }
            ITEM_DOMAIN => {
                let set = read_succinct(r)?;
                items.push(Item::DomainSet(set));
            }
            ITEM_DOMAIN_KEYWORD => {
                let v = read_strings(r)?;
                let desc = crate::strings::go_list("domain_keyword", &v);
                let pats: Vec<String> = v.iter().map(|k| regex::escape(k)).collect();
                let set = regex::RegexSet::new(&pats)
                    .map_err(|e| RuleSetParseError::Other(format!("domain_keyword: {e}")))?;
                items.push(Item::Keyword { set, desc });
            }
            ITEM_DOMAIN_REGEX => {
                let v = read_strings(r)?;
                let desc = crate::strings::go_list("domain_regex", &v);
                let set = regex::RegexSet::new(&v).map_err(|e| {
                    RuleSetParseError::Other(format!("domain_regex: error parsing regexp: {e}"))
                })?;
                items.push(Item::Regex { set, desc });
            }
            ITEM_SOURCE_IP_CIDR => {
                let ranges = read_ipset(r)?;
                items.push(Item::IpRanges(ranges, "source_ip_cidr=<binary>".into()));
            }
            ITEM_IP_CIDR => {
                let ranges = read_ipset(r)?;
                items.push(Item::IpRanges(ranges, "ip_cidr=<binary>".into()));
            }
            ITEM_ADGUARD_DOMAIN => {
                let matcher = crate::adguard::AdGuardMatcher::read(r)?;
                items.push(Item::AdGuard(matcher));
            }
            ITEM_NETWORK_TYPE => {
                // nil NetworkManager (CLI): item не добавляется вовсе —
                // правило без allItems матчит ВСЁ (rule_abstract: len==0 → true)
                let n = r.uvarint_usize()?;
                r.skip(n)?;
            }
            ITEM_NETWORK_IFACE_ADDR | ITEM_DEFAULT_IFACE_ADDR => {
                let n = r.uvarint_usize()?;
                for _ in 0..n {
                    if item_type == ITEM_NETWORK_IFACE_ADDR {
                        r.u8()?;
                    }
                    let cnt = r.uvarint_usize()?;
                    for _ in 0..cnt {
                        read_prefix(r)?;
                    }
                }
                items.push(Item::Never("network_interface_address=<binary>".into()));
            }
            other => {
                return Err(RuleSetParseError::Other(format!(
                    "unknown rule item type: {other}"
                )));
            }
        }
    }
}

/// InterfaceType → имя (constant/network.go: wifi/cellular/ethernet/other).
#[must_use]
pub fn iface_type_name(v: u8) -> String {
    match v {
        0 => "wifi".into(),
        1 => "cellular".into(),
        2 => "ethernet".into(),
        3 => "other".into(),
        other => other.to_string(),
    }
}
