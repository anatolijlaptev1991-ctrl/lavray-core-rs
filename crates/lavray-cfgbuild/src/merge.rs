// SPDX-License-Identifier: GPL-3.0-only

//! MergeJson (порт Go `cfgbuild/merge.go`, db/ConfigBuilder.cpp:32–68):
//! рекурсивный мерж объектов; массивы при отсутствии ключа — конкатенация
//! «+key» (src ++ dst) / «key+» (dst ++ src), иначе перезапись.

use crate::util::Obj;
use serde_json::Value;

/// Рекурсивно мержит src в dst (семантика 1:1 с C++-оракулом MergeJson).
pub fn merge_json(dst: &mut Obj, src: &Obj) {
    for (key, v_src) in src {
        if let Some(v_dst) = dst.get(key) {
            if let (Some(src_obj), Some(dst_obj)) = (v_src.as_object(), v_dst.as_object()) {
                let mut merged = dst_obj.clone();
                merge_json(&mut merged, src_obj);
                dst.insert(key.clone(), Value::Object(merged));
            } else {
                dst.insert(key.clone(), v_src.clone());
            }
            continue;
        }
        if let Some(src_arr) = v_src.as_array() {
            if let Some(key2) = key.strip_prefix('+') {
                let dst_arr = dst
                    .get(key2)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let mut merged = src_arr.clone();
                merged.extend(dst_arr);
                dst.insert(key2.to_string(), Value::Array(merged));
            } else if let Some(key2) = key.strip_suffix('+') {
                let dst_arr = dst
                    .get(key2)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let mut merged = dst_arr;
                merged.extend(src_arr.clone());
                dst.insert(key2.to_string(), Value::Array(merged));
            } else {
                dst.insert(key.clone(), v_src.clone());
            }
            continue;
        }
        dst.insert(key.clone(), v_src.clone());
    }
}

/// Нормализовать `cfg["outbounds"]` в массив (Build кладёт массив объектов).
#[must_use]
pub fn cfg_outbounds_any(cfg: &Obj) -> Vec<Value> {
    cfg.get("outbounds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}
