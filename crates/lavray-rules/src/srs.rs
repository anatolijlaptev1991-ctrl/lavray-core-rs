// SPDX-License-Identifier: GPL-3.0-only

//! Чтение бинарных .srs (порт common/srs/binary.go, версии 1–5):
//! magic «SRS» + version + zlib(uvarint count + правила). Домены —
//! succinct set, IP — диапазоны; описания `<binary>` (паритет CLI).

use crate::matcher::Item;
use crate::source::RuleSetParseError;
use crate::srs_items::{
    ITEM_ADGUARD_DOMAIN, ITEM_DEFAULT_IFACE_ADDR, ITEM_DOMAIN, ITEM_DOMAIN_KEYWORD,
    ITEM_DOMAIN_REGEX, ITEM_FINAL, ITEM_IP_CIDR, ITEM_NETWORK_IFACE_ADDR,
    ITEM_NETWORK_IS_CONSTRAINED, ITEM_NETWORK_IS_EXPENSIVE, ITEM_NETWORK_TYPE, ITEM_SOURCE_IP_CIDR,
    read_ipset, read_prefix, read_string_item, read_strings, read_succinct, read_u16_item,
};
use crate::srs_reader::Reader;
use std::io::Read as _;
use std::net::IpAddr;

pub(crate) const MAX_LOGICAL_DEPTH: usize = 100;

/// Прочитать .srs → правила (item'ы + invert).
///
/// # Errors
/// Битый magic/версия/zlib, неизвестные item-типы, malformed succinct set.
pub fn read_ruleset(raw: &[u8]) -> Result<Vec<BinaryRule>, RuleSetParseError> {
    if raw.len() < 4 || &raw[..3] != b"SRS" {
        return Err(RuleSetParseError::Other(
            "invalid sing-box rule-set file".into(),
        ));
    }
    let version = raw[3];
    if version == 0 || version > 5 {
        return Err(RuleSetParseError::Other(format!(
            "unsupported version: {version}"
        )));
    }
    let mut z = flate2::read::ZlibDecoder::new(&raw[4..]);
    let mut inflated = Vec::new();
    z.read_to_end(&mut inflated)
        .map_err(|e| RuleSetParseError::Other(format!("zlib: {e}")))?;
    let mut r = Reader {
        buf: &inflated,
        pos: 0,
    };
    let count = r.uvarint_usize()?;
    let mut rules = Vec::with_capacity(count.min(1 << 16));
    for _ in 0..count {
        rules.push(read_rule(&mut r, 0)?);
    }
    Ok(rules)
}

/// Одна запись правил binary: item'ы + флаги для `matches`.
pub struct BinaryRule {
    pub(crate) items: Vec<Item>,
    pub(crate) invert: bool,
}

/// Диапазон IP (netipx: from <= ip <= to в пределах одного семейства).
pub fn ip_in_range(ip: IpAddr, from: IpAddr, to: IpAddr) -> bool {
    match (ip, from, to) {
        (IpAddr::V4(a), IpAddr::V4(f), IpAddr::V4(t)) => f <= a && a <= t,
        (IpAddr::V6(a), IpAddr::V6(f), IpAddr::V6(t)) => f <= a && a <= t,
        _ => false,
    }
}

fn read_rule(r: &mut Reader, depth: usize) -> Result<BinaryRule, RuleSetParseError> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err(RuleSetParseError::Other(
            "logical rule nested too deep".into(),
        ));
    }
    let rule_type = r.u8()?;
    match rule_type {
        0 => read_default(r),
        1 => read_logical(r, depth),
        other => Err(RuleSetParseError::Other(format!(
            "unknown rule type: {other}"
        ))),
    }
}

fn read_logical(r: &mut Reader, depth: usize) -> Result<BinaryRule, RuleSetParseError> {
    // Логическое правило в binary: mode + подправила + invert — материализуем
    // в item'ы нельзя без расширения модели; ошибка домена (CLI-контекст
    // логических .srs не проверяется эталонными кейсами — подволнна 7f-3).
    let _mode = r.u8()?;
    let count = r.uvarint_usize()?;
    let mut sub = Vec::with_capacity(count.min(1 << 12));
    for _ in 0..count {
        sub.push(read_rule(r, depth + 1)?);
    }
    let _invert = r.u8()?;
    Err(RuleSetParseError::Other(format!(
        "logical binary rule ({} sub-rules) — подволнна 7f-3",
        sub.len()
    )))
}

fn read_default(r: &mut Reader) -> Result<BinaryRule, RuleSetParseError> {
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
                items.push(Item::Keyword { list: v, desc });
            }
            ITEM_DOMAIN_REGEX => {
                let v = read_strings(r)?;
                let desc = crate::strings::go_list("domain_regex", &v);
                let mut list = Vec::with_capacity(v.len());
                for pat in &v {
                    list.push(regex::Regex::new(pat).map_err(|e| {
                        RuleSetParseError::Other(format!("domain_regex: error parsing regexp: {e}"))
                    })?);
                }
                items.push(Item::Regex { list, desc });
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
                // AdGuard-матчер — отдельный формат; в 7f-3.
                return Err(RuleSetParseError::Other(
                    "adguard binary item — подволнна 7f-3".into(),
                ));
            }
            ITEM_NETWORK_TYPE => {
                let n = r.uvarint_usize()?;
                r.skip(n)?;
                items.push(Item::Never("network_type=<binary>".into()));
            }
            ITEM_NETWORK_IS_EXPENSIVE => items.push(Item::Never("network_is_expensive".into())),
            ITEM_NETWORK_IS_CONSTRAINED => items.push(Item::Never("network_is_constrained".into())),
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
