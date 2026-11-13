// SPDX-License-Identifier: GPL-3.0-only

//! Параметры сборки конфига (порт Go `cfgbuild/builder.go` BuildSettings и
//! вложенных структур). JSON-теги совпадают с Go — golden-векторы парсятся
//! тем же контрактом.

use serde::{Deserialize, Serialize};

/// Глобальные настройки мультиплексирования (§3.1.10).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MuxSettings {
    /// h2mux | smux | yamux.
    #[serde(default)]
    pub protocol: String,
    /// <= 0 — мультиплексирование выключено глобально.
    #[serde(default)]
    pub concurrency: i64,
    #[serde(default)]
    pub padding: bool,
    /// multiplex_status == 0 (default) → включён?
    #[serde(default)]
    pub default_on: bool,
}

/// Слушатель mixed (inbound.* из §5.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundSettings {
    /// default 127.0.0.1 (не-loopback требует auth — FR-UI-279).
    #[serde(default)]
    pub address: String,
    /// default 2080; <=0 — слушатель выключен.
    #[serde(default)]
    pub port: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_pass: String,
    /// {"inbounds":[...]} — добавка к сгенерированным.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub custom_inbound: String,
}

/// Внутренний TUN (tun.* из §5.4; kill-switch FR-UI-275).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunSettings {
    #[serde(default)]
    pub enabled: bool,
    /// default lavray-tun (darwin: utun9).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub interface_name: String,
    /// default 9000.
    #[serde(default)]
    pub mtu: i64,
    /// gvisor | system | mixed; default gvisor.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stack: String,
    #[serde(default)]
    pub strict_route: bool,
    /// +fd4c:4156:5259::1/126.
    #[serde(default)]
    pub ipv6: bool,
    /// FR-UI-151.
    #[serde(default)]
    pub fake_dns: bool,
    /// Многострочник имён процессов.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bypass_process: String,
    /// Многострочник CIDR.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bypass_cidr: String,
    /// Инвертирует ТОЛЬКО tun-списки (поправка №28).
    #[serde(default)]
    pub whitelist: bool,
    /// FR-UI-275: форсирует strict_route.
    #[serde(default)]
    pub kill_switch: bool,
}

/// Параметры tproxy-входа шлюза OpenWrt (tproxy.go).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TProxySettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub port: i64,
    /// Слушать и IPv6 (явное включение в шлюзе).
    #[serde(default)]
    pub ipv6: bool,
}

/// Параметры сборки, влияющие на конфиг (подмножество карты настроек).
/// `Default` = ZERO-значения (паритет Go json.Unmarshal частичного settings:
/// неуказанные поля → zero). Заполненные дефолты — [`default_settings`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSettings {
    /// log.level (default "info").
    #[serde(default)]
    pub log_level: String,
    /// security.allow_insecure_default (skip_cert).
    #[serde(default)]
    pub allow_insecure_default: bool,
    #[serde(default)]
    pub mux: MuxSettings,
    #[serde(default)]
    pub inbound: InboundSettings,
    #[serde(default)]
    pub tun: TunSettings,
    /// core.underlying_dns (dns-local); "" → пресет → "local".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub underlying_dns: String,
    /// routing.custom_global ({"rules":[...]}).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub custom_route_global: String,
    /// Каталог поставки .srs; "" → "geo".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub geo_dir: String,
    /// experimental.cache_file.path; "" → путь sing-box.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cache_file_path: String,
    /// Платформа для процессных правил ("" → runtime).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub goos: String,
    /// --platform openwrt: без процессных правил.
    #[serde(default)]
    pub openwrt: bool,
    #[serde(default)]
    pub tproxy: TProxySettings,
    /// Запросы к dns-remote напрямую, без detour.
    #[serde(default)]
    pub dns_remote_direct: bool,
}

/// Заполненные значения по умолчанию (порт Go `DefaultSettings`): применяется
/// ТОЛЬКО когда settings не передан целиком (nil). Частичный settings сохраняет
/// zero-значения неуказанных полей (иначе mixed-in включался бы там, где Go его
/// выключает — port=0).
#[must_use]
pub fn default_settings() -> BuildSettings {
    BuildSettings {
        log_level: "info".into(),
        mux: MuxSettings {
            protocol: "h2mux".into(),
            concurrency: -1,
            padding: false,
            default_on: false,
        },
        inbound: InboundSettings {
            address: "127.0.0.1".into(),
            port: 2080,
            ..Default::default()
        },
        tun: TunSettings {
            mtu: 9000,
            stack: "gvisor".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}
