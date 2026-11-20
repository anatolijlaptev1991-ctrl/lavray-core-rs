// SPDX-License-Identifier: GPL-3.0-only

//! MCP-сервер (Model Context Protocol, JSON-RPC 2.0 over stdio — по
//! строке на сообщение): инструменты управления ядром для агентов.
//! Методы: initialize, tools/list, tools/call (profiles_list,
//! profile_get, version, updates_check), ping.

use std::sync::Arc;

use lavray_store::Store;
use serde_json::{Value, json};

/// Запустить MCP-сервер (stdio). Блокирует до EOF stdin.
pub fn run(args: &[String]) -> i32 {
    let mut data = default_data_dir();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data" => {
                i += 1;
                let Some(d) = args.get(i) else {
                    eprintln!("lavray-core mcp: --data требует значение");
                    return 2;
                };
                data.clone_from(d);
            }
            other => {
                eprintln!("lavray-core mcp: неизвестный флаг {other:?}");
                return 2;
            }
        }
        i += 1;
    }
    let dir = std::path::Path::new(&data);
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("lavray-core mcp: каталог данных {data:?}: {e}");
        return 1;
    }
    let store = match Store::open(&dir.join("lavray.db")) {
        Ok(s) => Arc::new(std::sync::Mutex::new(s)),
        Err(e) => {
            eprintln!("lavray-core mcp: store: {e}");
            return 1;
        }
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(serve_stdin(store))
}

/// Цикл stdin → JSON-RPC → stdout.
async fn serve_stdin(store: Arc<std::sync::Mutex<Store>>) -> i32 {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();
    loop {
        line.clear();
        if stdin.read_line(&mut line).await.unwrap_or(0) == 0 {
            return 0; // EOF
        }
        let Ok(req) = serde_json::from_str::<Value>(line.trim()) else {
            continue; // не-JSON строки игнорируются
        };
        let resp = handle(&req, &store);
        let _ = stdout.write_all((resp.to_string() + "\n").as_bytes()).await;
        let _ = stdout.flush().await;
    }
}

fn handle(req: &Value, store: &Arc<std::sync::Mutex<Store>>) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(json!({}));

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "lavray-core", "version": env!("CARGO_PKG_VERSION")}
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": crate::mcp_tools::tools_list()})),
        "tools/call" => crate::mcp_tools::tools_call(&params, store),
        _ => Err(format!("неизвестный метод: {method}")),
    };

    match result {
        Ok(mut r) => {
            if method == "tools/call" {
                // MCP: результат вызова инструмента обёрнут в content
                let text = r.take();
                r = json!({
                    "content": [{"type": "text", "text": text.to_string()}]
                });
            }
            json!({"jsonrpc": "2.0", "id": id, "result": r})
        }
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32603, "message": e}
        }),
    }
}

/// Каталог данных по умолчанию: ./data рядом с бинарём.
#[must_use]
fn default_data_dir() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|d| d.join("data").to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "data".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Arc<std::sync::Mutex<Store>> {
        Arc::new(std::sync::Mutex::new(Store::open_memory().expect("store")))
    }

    #[test]
    fn initialize_result() {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = handle(&req, &store());
        assert_eq!(resp["result"]["serverInfo"]["name"], "lavray-core");
    }

    #[test]
    fn unknown_method_error() {
        let req = json!({"jsonrpc":"2.0","id":9,"method":"nope"});
        let resp = handle(&req, &store());
        assert!(resp.get("error").is_some());
    }

    #[test]
    fn tools_list_four() {
        let req = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        let resp = handle(&req, &store());
        let tools = resp["result"]["tools"].as_array().expect("tools");
        assert_eq!(tools.len(), 4);
    }

    #[test]
    fn profiles_list_structure() {
        let req = json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"profiles_list","arguments":{}}});
        let resp = handle(&req, &store());
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        let v: Value = serde_json::from_str(text).expect("json");
        for g in v["groups"].as_array().expect("groups") {
            assert!(g["group"].is_object());
            assert!(g["profiles"].is_array());
        }
    }

    #[test]
    fn version_tool() {
        let req = json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"version","arguments":{}}});
        let resp = handle(&req, &store());
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
    }
}
