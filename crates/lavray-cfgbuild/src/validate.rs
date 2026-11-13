// SPDX-License-Identifier: GPL-3.0-only

//! Проверка звена цепочки перед сборкой outbound'а (порт Go
//! `cfgbuild/validate_ent.go` + `transport_support.go`).

use crate::error::{Error, Result};
use lavray_model::{Profile, ProfileType};

/// Стабильная причина отказа для профиля с транспортом, которого нет в ядре.
pub const REASON_TRANSPORT_UNSUPPORTED: &str = "transport_unsupported";

/// Транспорты потока, которые sing-box ядра не поддерживает (XHTTP).
fn unsupported_transport(p: &Profile) -> String {
    let Some(s) = &p.stream else {
        return String::new();
    };
    if s.network == "xhttp" {
        s.network.clone()
    } else {
        String::new()
    }
}

/// Значение Profile.unsupported_reason ("<транспорт>_unsupported" или "").
#[must_use]
pub fn unsupported_reason(p: &Profile) -> String {
    let name = unsupported_transport(p);
    if name.is_empty() {
        String::new()
    } else {
        format!("{name}_unsupported")
    }
}

fn check_transport_supported(p: &Profile) -> Result<()> {
    let name = unsupported_transport(p);
    if name.is_empty() {
        return Ok(());
    }
    Err(Error::precondition(
        "stream.network",
        format!(
            "profile {}: транспорт {name} не поддерживается ядром; выберите другой сервер",
            p.id
        ),
    )
    .with_reason(REASON_TRANSPORT_UNSUPPORTED))
}

/// Проверить профиль-звено: транспорт, адрес/порт, reality не без ключа.
pub fn validate_ent(p: &Profile) -> Result<()> {
    check_transport_supported(p)?;
    // Адрес/порт custom internal живёт в JSON outbound'а — не валидируем.
    if p.r#type == ProfileType::CustomOutbound {
        return Ok(());
    }
    if p.address.trim().is_empty() {
        return Err(Error::invalid(
            "address",
            format!("profile {}: server address is empty", p.id),
        ));
    }
    if p.port <= 0 || p.port > 65535 {
        return Err(Error::invalid(
            "port",
            format!("profile {}: invalid port {}", p.id, p.port),
        ));
    }
    if let Some(s) = &p.stream {
        if s.security == "reality" && s.reality_public_key.trim().is_empty() {
            return Err(Error::invalid(
                "stream.reality_public_key",
                format!("profile {}: security=reality требует public_key", p.id),
            ));
        }
    }
    Ok(())
}
