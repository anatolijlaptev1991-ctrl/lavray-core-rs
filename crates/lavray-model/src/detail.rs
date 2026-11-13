// SPDX-License-Identifier: GPL-3.0-only

//! Типоспецифичная часть профиля (bean-иерархия nekoray) — паритет с Go
//! `model.Detail`. Сериализуется как внутренний объект под ключом `detail`
//! (тип определяется полем `Profile.type`, без тега варианта).

use serde::{Deserialize, Serialize};

/// SocksHttpBean (socks4/socks5/http), FR-UI-091.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocksHttpDetail {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proto: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
}

/// ShadowSocksBean, FR-UI-092.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksDetail {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub udp_over_tcp: i64,
}

/// VMessBean, FR-UI-093.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VMessDetail {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uuid: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub alter_id: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub security: String,
}

/// TrojanVLESSBean (trojan|vless по Profile.type), FR-UI-094.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrojanVlessDetail {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow: String,
}

/// NaiveBean, FR-UI-095 (внешнее ядро, за флагом enable_external_cores).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NaiveDetail {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proto: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub extra_headers: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub certificate: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub insecure_concurrency: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_logs: bool,
}

/// QUICBean(proxy_Hysteria2), FR-UI-096 (имена полей sing-box 1.14, LNB-35).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hysteria2Detail {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub obfs_password: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub upload_mbps: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub download_mbps: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_ports: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hop_interval: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alpn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_insecure: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_sni: bool,
}

/// QUICBean(proxy_TUIC), FR-UI-097 (всегда внутренний sing-box).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuicDetail {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uuid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub congestion_control: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub udp_relay_mode: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub zero_rtt_handshake: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub heartbeat: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alpn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_insecure: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_sni: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub udp_over_stream: bool,
}

/// CustomBean (FR-UI-099/100a/100b): internal | internal-full | external.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomDetail {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub core: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub external_core_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_suffix: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_template: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub mapping_port: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub socks_port: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub outbound_json: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub full_config_json: String,
}

/// ChainBean (FR-UI-098): порядок сверху вниз = порядок трафика.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainDetail {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_ids: Vec<i64>,
}

/// Типоспецифичная часть профиля (ровно одна, как oneof контракта).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detail {
    SocksHttp(SocksHttpDetail),
    Shadowsocks(ShadowsocksDetail),
    VMess(VMessDetail),
    TrojanVless(TrojanVlessDetail),
    Naive(NaiveDetail),
    Hysteria2(Hysteria2Detail),
    Tuic(TuicDetail),
    Custom(CustomDetail),
    Chain(ChainDetail),
}

impl Detail {
    /// Сериализовать в JSON-объект (без тега варианта — тип задаёт Profile.type).
    pub fn to_value(&self) -> serde_json::Value {
        match self {
            Self::SocksHttp(d) => serde_json::to_value(d),
            Self::Shadowsocks(d) => serde_json::to_value(d),
            Self::VMess(d) => serde_json::to_value(d),
            Self::TrojanVless(d) => serde_json::to_value(d),
            Self::Naive(d) => serde_json::to_value(d),
            Self::Hysteria2(d) => serde_json::to_value(d),
            Self::Tuic(d) => serde_json::to_value(d),
            Self::Custom(d) => serde_json::to_value(d),
            Self::Chain(d) => serde_json::to_value(d),
        }
        .unwrap_or(serde_json::Value::Null)
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip_serializing_if требует &i64
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
