// SPDX-License-Identifier: GPL-3.0-only

//! StreamSettings — V2Ray Stream Settings (порт `model/stream.go`,
//! fmt/V2RayStreamSettings.hpp; FR-UI-090a–090l). Типы socks/http/ss/vmess/
//! vless/trojan. Все поля `omitempty` → `skip_serializing_if`.

use serde::{Deserialize, Serialize};

/// Настройки потока транспорта (network/security/reality/mux).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamSettings {
    /// tcp(дефолт)|http|ws|grpc|httpupgrade|quic|xhttp.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network: String,
    /// tcp: none|http.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub header_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// FR-UI-090c.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ws_early_data_header: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub ws_early_data_max: i64,
    /// "" | tls | reality (reality — при непустом pbk, FR-UI-090i).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub security: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
    /// Через запятую.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alpn: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_insecure: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub certificate: String,
    /// "" = глобальный дефолт.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub utls_fingerprint: String,
    /// pbk — включает REALITY.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reality_public_key: String,
    /// sid.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reality_short_id: String,
    /// Зарезервировано (FR-UI-267).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reality_spx: String,
    /// "" | packetaddr | xudp.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub packet_encoding: String,
    /// 0 default | 1 on | 2 off.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub multiplex: i64,
    /// XHTTP (Xray): ядро транспорта не имеет, хранится ради круга ссылка↔профиль.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub xhttp_mode: String,
    /// Сырой JSON параметра extra.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub xhttp_extra: String,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip_serializing_if требует &i64
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
