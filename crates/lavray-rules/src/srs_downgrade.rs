// SPDX-License-Identifier: GPL-3.0-only

//! Downgrade-семантика версии при compile (порт downgradeRuleSetVersion).

use crate::source::{HeadlessRule, PlainRuleSet};

/// Порт downgradeRuleSetVersion (compile): 3 → 2 при отсутствии
/// network_type/network_is_expensive/network_is_constrained во ВСЕХ правилах.
pub(crate) fn downgrade_version(set: &PlainRuleSet) -> u8 {
    let has_v3 = default_rules(&set.rules)
        .any(|d| !d.network_type.is_empty() || d.network_is_expensive || d.network_is_constrained);
    if has_v3 { 3 } else { 2 }
}

/// Плоский проход по default-правилам (в т.ч. внутри logical).
fn default_rules(rules: &[HeadlessRule]) -> impl Iterator<Item = &crate::source::DefaultRule> {
    let mut stack: Vec<&HeadlessRule> = rules.iter().collect();
    std::iter::from_fn(move || {
        while let Some(r) = stack.pop() {
            match r {
                HeadlessRule::Default(d) => return Some(&**d),
                HeadlessRule::Logical(l) => stack.extend(l.rules.iter()),
                HeadlessRule::Empty => {}
            }
        }
        None
    })
}
