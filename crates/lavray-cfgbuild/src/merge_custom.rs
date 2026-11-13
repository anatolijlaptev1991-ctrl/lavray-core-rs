// SPDX-License-Identifier: GPL-3.0-only

//! Allowlist-мерж пользовательского custom_config (порт Go `cfgbuild/merge.go`,
//! §3.1.1/LNB-25). Вне белого списка корневых секций → InvalidArgument.
//! log — только level; experimental — только cache_file (без path); outbounds —
//! только собственные теги профиля.

use crate::error::{Error, Result};
use crate::filekeys::{merge_key_base, reject_file_keys};
use crate::merge::{cfg_outbounds_any, merge_json};
use crate::util::Obj;
use serde_json::{json, Value};

const ALLOWED_ROOT_KEYS: &[&str] = &["route", "dns", "outbounds", "log", "experimental"];
const CACHE_FILE_KEYS: &[&str] = &[
    "enabled",
    "cache_id",
    "store_fakeip",
    "store_rdrc",
    "store_dns",
    "rdrc_timeout",
];

/// Валидировать custom_config по allowlist и смержить в готовый конфиг.
pub fn merge_custom_config(
    cfg: &mut Obj,
    src_json: &str,
    allowed_outbound_tags: &[String],
) -> Result<()> {
    let src_json = src_json.trim();
    if src_json.is_empty() || src_json == "{}" {
        return Ok(());
    }
    let src: Obj = serde_json::from_str(src_json)
        .map_err(|e| Error::invalid("custom_config", format!("invalid JSON: {e}")))?;

    let mut root_keys: Vec<&String> = src.keys().collect();
    root_keys.sort();
    for key in root_keys {
        let val = &src[key];
        let base = merge_key_base(key);
        if key != &base && !val.is_array() {
            return Err(Error::invalid(
                base.clone(),
                format!("concat marker {key:?} requires an array value"),
            ));
        }
        if !ALLOWED_ROOT_KEYS.contains(&base.as_str()) {
            return Err(Error::invalid(
                base.clone(),
                format!("key {base:?} is not allowed in custom_config (allowlist: route, dns, outbounds, log.level, experimental.cache_file)"),
            ));
        }
        if matches!(base.as_str(), "route" | "dns" | "outbounds") {
            let wrapper = json!({ base.clone(): val.clone() });
            reject_file_keys("", &wrapper)?;
        }
        match base.as_str() {
            "route" | "dns" => {
                if !val.is_object() {
                    return Err(Error::invalid(
                        base.clone(),
                        format!("{base} override must be an object"),
                    ));
                }
                let mut patch = Obj::new();
                patch.insert(key.clone(), val.clone());
                merge_json(cfg, &patch);
            }
            "log" => merge_log_key(cfg, key, val)?,
            "experimental" => merge_experimental_key(cfg, key, val)?,
            "outbounds" => merge_outbounds_key(cfg, val, allowed_outbound_tags)?,
            _ => {}
        }
    }
    Ok(())
}

fn merge_log_key(cfg: &mut Obj, key: &str, val: &Value) -> Result<()> {
    let obj = val
        .as_object()
        .ok_or_else(|| Error::invalid("log", "log override must be an object"))?;
    for sub in obj.keys() {
        if merge_key_base(sub) != "level" {
            let k = format!("log.{}", merge_key_base(sub));
            return Err(Error::invalid(
                k.clone(),
                format!("key {k:?} is not allowed in custom_config (only log.level)"),
            ));
        }
    }
    let mut patch = Obj::new();
    patch.insert(key.to_string(), val.clone());
    merge_json(cfg, &patch);
    Ok(())
}

fn merge_experimental_key(cfg: &mut Obj, key: &str, val: &Value) -> Result<()> {
    let obj = val
        .as_object()
        .ok_or_else(|| Error::invalid("experimental", "experimental override must be an object"))?;
    let mut subs: Vec<&String> = obj.keys().collect();
    subs.sort();
    for sub in subs {
        if merge_key_base(sub) != "cache_file" {
            let k = format!("experimental.{}", merge_key_base(sub));
            return Err(Error::invalid(
                k.clone(),
                format!("key {k:?} is not allowed in custom_config (only experimental.cache_file)"),
            ));
        }
        let cache_file = obj[sub].as_object().ok_or_else(|| {
            Error::invalid(
                "experimental.cache_file",
                "experimental.cache_file override must be an object",
            )
        })?;
        let mut fields: Vec<&String> = cache_file.keys().collect();
        fields.sort();
        for field in fields {
            if !CACHE_FILE_KEYS.contains(&field.as_str()) {
                let k = format!("experimental.cache_file.{}", merge_key_base(field));
                return Err(Error::invalid(
                    k.clone(),
                    format!("key {k:?} is not allowed in custom_config (cache_file accepts only enabled, cache_id, store_fakeip, store_rdrc, store_dns, rdrc_timeout; the cache file path is set by LAVRay)"),
                ));
            }
        }
    }
    let mut patch = Obj::new();
    patch.insert(key.to_string(), val.clone());
    merge_json(cfg, &patch);
    Ok(())
}

fn merge_outbounds_key(cfg: &mut Obj, val: &Value, allowed_tags: &[String]) -> Result<()> {
    let arr = val
        .as_array()
        .ok_or_else(|| Error::invalid("outbounds", "outbounds override must be an array"))?;
    // Проверка тегов по снапшоту (паритет: чужие/отсутствующие теги — ошибка).
    let cfg_arr = cfg_outbounds_any(cfg);
    for (i, el) in arr.iter().enumerate() {
        let obj = el.as_object().ok_or_else(|| {
            Error::invalid(
                format!("outbounds[{i}]"),
                "outbound override must be an object",
            )
        })?;
        let tag = obj.get("tag").and_then(Value::as_str).unwrap_or("");
        if tag.is_empty() {
            return Err(Error::invalid(
                format!("outbounds[{i}]"),
                "outbound override must have a tag",
            ));
        }
        if !allowed_tags.iter().any(|t| t == tag) {
            return Err(Error::invalid(
                "outbounds",
                format!("tag {tag:?} is not an outbound of this profile"),
            ));
        }
        let exists = cfg_arr
            .iter()
            .any(|d| d.get("tag").and_then(Value::as_str) == Some(tag));
        if !exists {
            return Err(Error::invalid(
                "outbounds",
                format!("tag {tag:?} is not an outbound of this profile"),
            ));
        }
    }
    // Мерж по тегу в существующий outbound (на месте).
    if let Some(Value::Array(dst_arr)) = cfg.get_mut("outbounds") {
        for el in arr {
            let Some(obj) = el.as_object() else { continue };
            let tag = obj.get("tag").and_then(Value::as_str).unwrap_or("");
            for d in dst_arr.iter_mut() {
                if d.get("tag").and_then(Value::as_str) == Some(tag) {
                    if let Some(dst_obj) = d.as_object_mut() {
                        merge_json(dst_obj, obj);
                    }
                    break;
                }
            }
        }
    }
    Ok(())
}
