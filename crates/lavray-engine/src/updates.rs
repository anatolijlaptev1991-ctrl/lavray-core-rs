// SPDX-License-Identifier: GPL-3.0-only

//! Проверка обновлений ядра (волна updates): GitHub Releases latest →
//! semver-сравнение с текущей версией → `UpdateInfo` для CLI
//! (`lavray-core updates check`). HTTPS GET — mini-клиент на rustls
//! (паттерн lavray-dns doh_client).

use serde_json::Value;

/// Текущая версия ядра — из манифеста workspace (единый источник версии).
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Репозиторий проекта по умолчанию.
pub const DEFAULT_REPO: &str = "anatolijlaptev1991-ctrl/lavray-core-rs";

/// Результат проверки обновлений.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateInfo {
    /// Свежий тег релиза (как в GitHub, обычно с `v`).
    pub latest: String,
    /// Текущая версия (для сравнения).
    pub current: String,
    /// HTML-страница релиза.
    pub url: String,
    /// latest новее текущей.
    pub newer: bool,
}

/// Разобрать ответ GitHub `/releases/latest`: (tag_name, html_url).
#[must_use]
pub fn parse_release_json(json: &str) -> Option<(String, String)> {
    let v: Value = serde_json::from_str(json).ok()?;
    let tag = v.get("tag_name")?.as_str()?.to_string();
    let url = v
        .get("html_url")
        .and_then(|u| u.as_str())
        .unwrap_or_default()
        .to_string();
    Some((tag, url))
}

/// «v1.2.3» / «1.2.3-rc» → (1, 2, 3); не-числа → 0.
#[must_use]
pub fn parse_version(tag: &str) -> (u64, u64, u64) {
    let core = tag.trim_start_matches('v');
    let mut it = core.split(['.', '-', '+']);
    // не-семверный тег («release-42») → (0,0,0): сравнение не предложит
    // обновление на мусорный тег
    let Some(major_str) = it.next().map(std::string::ToString::to_string) else {
        return (0, 0, 0);
    };
    let Ok(major) = major_str.parse::<u64>() else {
        return (0, 0, 0);
    };
    let get = |s: Option<&str>| -> u64 { s.and_then(|p| p.parse::<u64>().ok()).unwrap_or(0) };
    (major, get(it.next()), get(it.next()))
}

/// `latest` новее `current`?
#[must_use]
pub fn is_newer(latest: &str, current: &str) -> bool {
    parse_version(latest) > parse_version(current)
}

/// Проверить обновления: GitHub Releases latest против текущей версии.
///
/// # Errors
/// Сеть / HTTP / JSON.
pub async fn check(repo: &str, current: &str) -> Result<UpdateInfo, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let response = Box::pin(crate::updates_http::https_get(&url))
        .await
        .map_err(|e| e.to_string())?;
    let body = crate::updates_http::http_body(&response).map_err(|e| e.to_string())?;
    let json = String::from_utf8_lossy(&body).into_owned();
    let Some((tag, page)) = parse_release_json(&json) else {
        return Err("release json: нет tag_name".into());
    };
    Ok(UpdateInfo {
        newer: is_newer(&tag, current),
        latest: tag,
        current: current.to_string(),
        url: page,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_release_json_golden() {
        let json = r#"{"url":"u","html_url":"https://github.com/x/releases/tag/v1.2.3","tag_name":"v1.2.3","name":"r"}"#;
        let (tag, url) = parse_release_json(json).expect("parse");
        assert_eq!(tag, "v1.2.3");
        assert_eq!(url, "https://github.com/x/releases/tag/v1.2.3");
    }

    #[test]
    fn parse_release_json_bad() {
        assert!(parse_release_json("not json").is_none());
        assert!(parse_release_json("{}").is_none());
    }

    #[test]
    fn version_compare() {
        assert!(is_newer("v0.9.4", "0.9.3"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("v0.9.3", "0.9.3"));
        assert!(!is_newer("0.9.2", "0.9.10"));
        assert!(is_newer("0.10.0", "0.9.10"));
        assert!(!is_newer("release-42", "0.0.1")); // не семвер → (0,0,0)
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Живой тест (сеть): публичный репозиторий с релизами.
    #[tokio::test]
    #[ignore = "network"]
    async fn check_public_repo() {
        let info = check("torvalds/linux", "5.0").await.expect("check");
        assert!(info.newer, "linux 6.x новее 5.0");
        assert_ne!(info.url, "");
    }
}
