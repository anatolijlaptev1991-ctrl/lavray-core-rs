// SPDX-License-Identifier: GPL-3.0-only

//! AdGuard-матчер (порт sing/common/domain/adguard_matcher.go): правила
//! ||x.com^ / |x^ / x^ / *-подстановки поверх succinct set. Чтение из
//! .srs (binary item 16) + матчинг с рекурсией (maxDepth 100).

use crate::succinct::SuccinctSet;

const ANY_LABEL: u8 = b'*';
const SUFFIX_LABEL: u8 = 0x08; // '\b' в Go
const ROOT_LABEL: u8 = b'\n';
const PREFIX_LABEL: u8 = b'\r';
const MAX_DEPTH: usize = 100;

/// AdGuard-матчер поверх succinct set.
#[derive(Debug, Clone)]
pub struct AdGuardMatcher {
    set: SuccinctSet,
}

impl AdGuardMatcher {
    /// Собрать из строк правил (||domain^, |start^, keyword^, *wild^).
    #[must_use]
    pub fn new(rule_lines: &[String]) -> Self {
        let mut rule_list: Vec<String> = Vec::with_capacity(rule_lines.len());
        for line in rule_lines {
            let mut is_suffix = false; // ||
            let mut has_start = false; // |
            let mut has_end = false; // ^
            let mut rule = line.as_str();
            if let Some(rest) = rule.strip_prefix("||") {
                rule = rest;
                is_suffix = true;
            } else if let Some(rest) = rule.strip_prefix('|') {
                rule = rest;
                has_start = true;
            }
            if let Some(rest) = rule.strip_suffix('^') {
                rule = rest;
                has_end = true;
            }
            let mut labeled = String::new();
            if is_suffix {
                labeled.push(ROOT_LABEL as char);
            } else if !has_start {
                labeled.push(PREFIX_LABEL as char);
            }
            labeled.push_str(rule);
            if !has_end {
                let trimmed = labeled.strip_suffix('.').unwrap_or(&labeled);
                labeled = format!("{trimmed}{}", SUFFIX_LABEL as char);
            }
            rule_list.push(crate::strings::reverse_domain(&labeled));
        }
        rule_list.sort();
        rule_list.dedup();
        let keys: Vec<Vec<u8>> = rule_list
            .iter()
            .map(|k| k.chars().map(|c| c as u8).collect())
            .collect();
        let (leaves, label_bitmap, labels) = crate::srs_build::build_succinct(&keys);
        let set = SuccinctSet::from_parts(leaves, label_bitmap, labels)
            .unwrap_or_else(|_| unreachable!("собственный succinct валиден"));
        Self { set }
    }

    /// Прочитать из .srs-потока (формат = succinct set Write).
    ///
    /// # Errors
    /// `domain: malformed succinct set` при битых инвариантах.
    pub(crate) fn read(
        r: &mut crate::srs_reader::Reader<'_>,
    ) -> Result<Self, crate::source::RuleSetParseError> {
        let _marker = r.u8()?;
        let leaves = r.u64_be_slice()?;
        let label_bitmap = r.u64_be_slice()?;
        let labels = r.bytes()?;
        Ok(Self {
            set: SuccinctSet::from_parts(leaves, label_bitmap, labels)
                .map_err(crate::source::RuleSetParseError::Other)?,
        })
    }

    /// Матчинг домена (Match() Go): точный/суффикс-спуск + под-домены.
    #[must_use]
    pub fn is_match(&self, domain: &str) -> bool {
        let mut key = crate::strings::reverse_domain(domain).into_bytes();
        if self.has(&key, 0, 0, 0) {
            return true;
        }
        loop {
            // суффикс-форма: suffixLabel + ключ
            let mut with_suffix = vec![SUFFIX_LABEL];
            with_suffix.extend_from_slice(&key);
            if self.has(&with_suffix, 0, 0, 0) {
                return true;
            }
            let Some(idx) = key.iter().position(|&b| b == b'.') else {
                return false;
            };
            key.drain(..=idx);
        }
    }

    fn has(&self, key: &[u8], node_id: usize, bm_idx: usize, depth: usize) -> bool {
        self.has_with_depth(key, node_id, bm_idx, depth)
    }

    fn has_with_depth(
        &self,
        key: &[u8],
        mut node_id: usize,
        mut bm_idx: usize,
        depth: usize,
    ) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }
        let key_len = key.len();
        for i in 0..key_len {
            let current_char = key[i];
            loop {
                if SuccinctSet::get_bit(&self.set.label_bitmap, bm_idx) {
                    return false;
                }
                let next_label = self.set.labels[bm_idx - node_id];
                if next_label == PREFIX_LABEL {
                    return true;
                }
                if next_label == ROOT_LABEL {
                    let next_node_id = self.set.count_zeros(bm_idx + 1);
                    let has_next = SuccinctSet::get_bit(&self.set.leaves, next_node_id);
                    if current_char == b'.' && has_next {
                        return true;
                    }
                }
                if next_label == current_char {
                    break;
                }
                if next_label == ANY_LABEL || next_label == SUFFIX_LABEL {
                    let next_node_id = self.set.count_zeros(bm_idx + 1);
                    let next_bm_idx = self.set.select_ith_one(next_node_id - 1) + 1;
                    if self.has_with_depth(&key[i..], next_node_id, next_bm_idx, depth + 1) {
                        return true;
                    }
                    for j in i + 1..=key_len {
                        if self.has_with_depth(&key[j..], next_node_id, next_bm_idx, depth + 1) {
                            return true;
                        }
                    }
                }
                bm_idx += 1;
            }
            node_id = self.set.count_zeros(bm_idx + 1);
            bm_idx = self.set.select_ith_one(node_id - 1) + 1;
        }
        if SuccinctSet::get_bit(&self.set.leaves, node_id) {
            return true;
        }
        loop {
            if SuccinctSet::get_bit(&self.set.label_bitmap, bm_idx) {
                return false;
            }
            let next_label = self.set.labels[bm_idx - node_id];
            if next_label == PREFIX_LABEL || next_label == ROOT_LABEL || next_label == SUFFIX_LABEL
            {
                return true;
            }
            if next_label == ANY_LABEL {
                let next_node_id = self.set.count_zeros(bm_idx + 1);
                let next_bm_idx = self.set.select_ith_one(next_node_id - 1) + 1;
                return self.has_with_depth(&[], next_node_id, next_bm_idx, depth + 1);
            }
            bm_idx += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_built_and_matched() {
        let m = AdGuardMatcher::new(&["||example.com^".to_string(), "|exact.org^".to_string()]);
        assert!(m.is_match("example.com"));
        assert!(m.is_match("sub.example.com"));
        assert!(m.is_match("exact.org"));
        assert!(!m.is_match("exact.org.evil.com"));
        assert!(!m.is_match("other.com"));
    }
}
