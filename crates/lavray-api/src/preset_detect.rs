// SPDX-License-Identifier: GPL-3.0-only

//! ImportPreset: формат-детект (LAVRay по ключу routing / NekoRay по
//! nekoKeys) и вставка нового пользовательского набора (вынесено из
//! preset_io.rs трещоткой; волна 6.5 — конвертер NekoRay подключён).

#![allow(clippy::result_large_err)] // tonic::Status велик по природе контракта

use lavray_presets::{
    ConvertMeta, SCHEMA_VERSION, convert_neko_route, load_preset, parse_neko_route,
};
use lavray_store::Store;
use std::sync::MutexGuard;
use tonic::Status;

use super::preset_io::{MAX_IMPORT_BYTES, insert_imported};
use lavray_proto::v1 as pb;

/// Ключи маршрута NekoRay (Go nekoKeys).
const NEKO_KEYS: [&str; 6] = [
    "domainStrategy",
    "rules",
    "conn",
    "bypass_lan",
    "bypass_chn",
    "bypass_gfw",
];

/// Импорт файла: LAVRay или маршрут NekoRay → новый пользовательский набор.
pub(super) fn import_preset(
    st: &MutexGuard<'_, Store>,
    json: &str,
) -> Result<(pb::RoutingPreset, Vec<String>), Status> {
    if json.len() > MAX_IMPORT_BYTES {
        return Err(Status::resource_exhausted(format!(
            "файл больше {MAX_IMPORT_BYTES} байт"
        )));
    }
    let top: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(json).map_err(|e| {
            Status::invalid_argument(format!("формат файла: ожидался JSON-объект: {e}"))
        })?;
    if top.get("routing").is_none() {
        if NEKO_KEYS.iter().any(|k| top.contains_key(*k)) {
            let src = parse_neko_route(json).map_err(Status::invalid_argument)?;
            let name = top
                .get("__name__")
                .and_then(|v| v.as_str())
                .unwrap_or("NekoRay")
                .to_string();
            let (p, _warnings) = convert_neko_route(
                &src,
                &ConvertMeta {
                    id: "custom:import".into(),
                    name,
                },
            )
            .map_err(|e| Status::invalid_argument(e.0))?;
            let out = insert_imported(st, p)?;
            return Ok((out, Vec::new()));
        }
        return Err(Status::invalid_argument(
            "формат файла: нет ни routing, ни полей маршрута NekoRay",
        ));
    }
    // Вставка выставит свою версию схемы — версию файла проверяем здесь.
    let version = top
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if version == 0 || version > u64::from(SCHEMA_VERSION) {
        return Err(Status::invalid_argument(format!(
            "версия схемы {version} не поддерживается (поддерживается ≤ {SCHEMA_VERSION})"
        )));
    }
    let p = load_preset(json).map_err(|e| Status::invalid_argument(e.0))?;
    let out = insert_imported(st, p)?;
    Ok((out, Vec::new()))
}
