// SPDX-License-Identifier: GPL-3.0-only

//! Чтение бинарных .srs (порт common/srs/binary.go, версии 1–5):
//! magic «SRS» + version + zlib(uvarint count + правила). Домены —
//! succinct set, IP — диапазоны; описания `<binary>` (паритет CLI).

use crate::items::Item;
use crate::meta::MatchMeta;
use crate::source::RuleSetParseError;

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
#[derive(Debug, Clone)]
pub struct BinaryRule {
    pub(crate) items: Vec<Item>,
    pub(crate) invert: bool,
}

/// Матчинг binary-правила (AND item'ов, invert) — общий для top-level
/// и логических подправил. Пустое правило матчит ВСЁ (Go: len(allItems)==0).
#[must_use]
pub(crate) fn binary_rule_matches(rule: &[Item], invert: bool, meta: &MatchMeta) -> bool {
    let m = rule.is_empty() || rule.iter().all(|it| it.matches(meta));
    m != invert
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
        0 => crate::srs_default::read_default(r),
        1 => read_logical(r, depth),
        other => Err(RuleSetParseError::Other(format!(
            "unknown rule type: {other}"
        ))),
    }
}

fn read_logical(r: &mut Reader, depth: usize) -> Result<BinaryRule, RuleSetParseError> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err(RuleSetParseError::Other(
            "logical rule nested too deep".into(),
        ));
    }
    let mode = r.u8()?;
    if mode > 1 {
        return Err(RuleSetParseError::Other(format!(
            "unknown logical mode: {mode}"
        )));
    }
    let count = r.uvarint_usize()?;
    let mut sub = Vec::with_capacity(count.min(1 << 12));
    for _ in 0..count {
        sub.push(read_rule(r, depth + 1)?);
    }
    let invert = r.u8()? != 0;
    Ok(BinaryRule {
        items: vec![Item::Logical {
            mode_or: mode == 1,
            sub,
            invert,
        }],
        invert: false,
    })
}
