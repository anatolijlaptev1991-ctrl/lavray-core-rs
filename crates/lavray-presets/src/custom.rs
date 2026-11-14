// SPDX-License-Identifier: GPL-3.0-only

//! Пользовательская копия набора и приведение к хранимому виду (порт Go
//! `presets/custom.go` + `presets/limits.go`): «Сохранить как», «Дублировать»,
//! правка встроенного через копию; Create/Update/Import вызывают PrepareUser.

use crate::limits::{MAX_LIST_ENTRIES, MAX_NAME_RUNES, MAX_PROCESS_NAMES, MAX_PROCESS_RULES};
use crate::types::{Preset, SCHEMA_VERSION};
use crate::validate::ValidationError;

/// Значение `$schema` в файлах наборов (как у встроенных).
pub const SCHEMA_REF: &str = "preset.schema.v1.json";

/// Новая пользовательская копия `src` под новым id: не builtin, ревизия 1,
/// версия схемы текущая. Источник: у встроенного — он сам (id и ревизия);
/// у пользовательского — его собственный источник; у набора «с нуля» — нет.
/// `src` не меняется.
#[must_use]
pub fn new_custom_from(src: &Preset, id: &str) -> Preset {
    let mut c = src.clone();
    c.schema = SCHEMA_REF.into();
    c.version = SCHEMA_VERSION;
    c.revision = 1;
    c.id = id.into();
    c.builtin = false;
    if src.builtin {
        c.source_id.clone_from(&src.id);
        c.source_revision = src.revision;
    }
    c
}

/// Привести пользовательский набор к хранимому виду и проверить: custom_rules
/// → массив, лимиты пользователя, затем Validate по схеме. Ошибки называют
/// путь поля (порт Go `Preset.PrepareUser`).
pub fn prepare_user(p: &mut Preset) -> Result<(), ValidationError> {
    let rules = crate::normalize_custom_rules(&p.routing.custom_rules)
        .map_err(|e| ValidationError(format!("routing.custom_rules: {e}")))?;
    p.routing.custom_rules = rules;
    check_user_limits(p)?;
    p.validate()
}

fn check_user_limits(p: &Preset) -> Result<(), ValidationError> {
    let mut named = false;
    for (lang, name) in p.name.iter() {
        let n = name.chars().count();
        if n > MAX_NAME_RUNES {
            return Err(ValidationError(format!(
                "name.{lang}: {n} символов, предел {MAX_NAME_RUNES}"
            )));
        }
        named = named || !name.trim().is_empty();
    }
    if !named {
        return Err(ValidationError("name: пустое имя".into()));
    }
    let r = &p.routing;
    for (path, items) in [
        ("routing.proxy_domain", &r.proxy_domain),
        ("routing.direct_domain", &r.direct_domain),
        ("routing.block_domain", &r.block_domain),
        ("routing.proxy_ip", &r.proxy_ip),
        ("routing.direct_ip", &r.direct_ip),
        ("routing.block_ip", &r.block_ip),
    ] {
        if items.len() > MAX_LIST_ENTRIES {
            return Err(ValidationError(format!(
                "{path}: {} записей, предел {MAX_LIST_ENTRIES}",
                items.len()
            )));
        }
    }
    if r.process_rules.len() > MAX_PROCESS_RULES {
        return Err(ValidationError(format!(
            "routing.process_rules: {} правил, предел {MAX_PROCESS_RULES}",
            r.process_rules.len()
        )));
    }
    for (i, pr) in r.process_rules.iter().enumerate() {
        if pr.process_names.len() > MAX_PROCESS_NAMES {
            return Err(ValidationError(format!(
                "routing.process_rules[{i}].process_names: {} имён, предел {MAX_PROCESS_NAMES}",
                pr.process_names.len()
            )));
        }
    }
    Ok(())
}
