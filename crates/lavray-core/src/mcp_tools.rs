// SPDX-License-Identifier: GPL-3.0-only

//! MCP-инструменты: список/описание и вызовы против store/движка.

use lavray_store::Store;
use serde_json::{Value, json};
use std::sync::Arc;

pub fn tools_list() -> Value {
    json!([
        {"name": "profiles_list", "description": "Список групп и профилей хранилища",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "profile_get", "description": "Профиль по id",
         "inputSchema": {"type": "object",
             "required": ["id"],
             "properties": {"id": {"type": "integer"}}}},
        {"name": "version", "description": "Версия ядра",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "updates_check", "description": "Свежий релиз на GitHub (repo опционален)",
         "inputSchema": {"type": "object",
             "properties": {"repo": {"type": "string"}}}},
    ])
}

pub fn tools_call(params: &Value, store: &Arc<std::sync::Mutex<Store>>) -> Result<Value, String> {
    let name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or("tools/call: нет name")?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    match name {
        "profiles_list" => {
            let st = store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let groups = st.list_groups().map_err(|e| e.to_string())?;
            let mut items = Vec::new();
            for g in groups {
                let profiles = st.list_profiles(g.id).map_err(|e| e.to_string())?;
                items.push(json!({
                    "group": {"id": g.id, "name": g.name},
                    "profiles": profiles.iter().map(|p| json!({
                        "id": p.id, "type": format!("{:?}", p.r#type),
                        "name": p.name, "address": p.address, "port": p.port,
                    })).collect::<Vec<_>>()
                }));
            }
            Ok(json!({"groups": items}))
        }
        "profile_get" => {
            let id = args
                .get("id")
                .and_then(serde_json::Value::as_i64)
                .ok_or("profile_get: нет id")?;
            let st = store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let p = st.get_profile(id).map_err(|e| e.to_string())?;
            Ok(json!({
                "id": p.id, "type": format!("{:?}", p.r#type),
                "name": p.name, "address": p.address, "port": p.port,
                "notes": p.notes,
            }))
        }
        "version" => Ok(json!({"version": env!("CARGO_PKG_VERSION")})),
        "updates_check" => {
            let repo = args
                .get("repo")
                .and_then(|v| v.as_str())
                .unwrap_or(lavray_engine::updates::DEFAULT_REPO)
                .to_string();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let info = rt.block_on(lavray_engine::updates::check(
                &repo,
                lavray_engine::updates::CURRENT_VERSION,
            ))?;
            Ok(json!({
                "current": info.current, "latest": info.latest,
                "newer": info.newer, "url": info.url,
            }))
        }
        _ => Err(format!("неизвестный инструмент: {name}")),
    }
}
