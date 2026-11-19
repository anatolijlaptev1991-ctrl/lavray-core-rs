// SPDX-License-Identifier: GPL-3.0-only

//! lavray-sbconfig: валидация (`check`) и форматирование (`format`)
//! конфига sing-box — паритет вердиктов и текстов ошибок Go 1.14.1
//! (recorded behavior, `rust/app-cases/check-*|format-*`).

pub mod gojson;
pub mod schema;
pub mod walk;

/// Результат check: Ok или текст БЕЗ префикса «FATAL[0000] ».
pub enum CheckStage {
    /// Всё валидно.
    Ok,
    Read(String),
    Decode(String),
    Router(String),
}

/// Проверить конфиг: `raw` — содержимое, `path` — путь для сообщлений.
///
/// # Errors
/// Стадия + текст ошибки в стиле Go.
pub fn check(raw: &str, path: &str, cwd: &std::path::Path) -> CheckStage {
    let root: serde_json::Map<String, serde_json::Value> = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            let text = gojson::syntax_error_text(raw, &e.to_string());
            return CheckStage::Decode(format!("decode config at {path}: {text}"));
        }
    };
    if let Err(text) = walk::walk(&root) {
        return CheckStage::Decode(format!("decode config at {path}: {text}"));
    }
    // initialize router: локальные rule-set обязаны существовать.
    for (i, rel) in walk::ruleset_paths(&root) {
        let abs = absolutize(cwd, &rel);
        if !abs.exists() {
            return CheckStage::Router(format!(
                "initialize router: parse rule-set[{i}]: open {}: The system cannot find the file specified.",
                abs.display()
            ));
        }
    }
    CheckStage::Ok
}

pub enum FormatOutcome {
    /// Отформатированный pretty-JSON (2 пробела, порядок ключей входа).
    Formatted(String),
    /// `decode config at <path>: <текст>`.
    DecodeError(String),
}

/// Форматировать конфиг (паритет `sing-box format`).
#[must_use]
pub fn format_config(raw: &str, path: &str) -> FormatOutcome {
    let root: serde_json::Map<String, serde_json::Value> = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            let text = gojson::syntax_error_text(raw, &e.to_string());
            return FormatOutcome::DecodeError(format!("decode config at {path}: {text}"));
        }
    };
    match serde_json::to_string_pretty(&root) {
        Ok(out) => FormatOutcome::Formatted(out),
        Err(e) => FormatOutcome::DecodeError(format!("decode config at {path}: {e}")),
    }
}

fn absolutize(cwd: &std::path::Path, rel: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(rel);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}
