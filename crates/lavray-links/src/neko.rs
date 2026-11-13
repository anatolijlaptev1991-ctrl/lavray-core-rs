// SPDX-License-Identifier: GPL-3.0-only

//! nekoray://<type>#<base64url(JSON bean)> — FR-UI-191, полное сохранение полей
//! профиля (порт Go `links/neko.go` parseNekoLink). Фикс P2-10 аудита.
//! c_cfg/c_out ЭКСПОРТИРУЮТСЯ, но на ИМПОРТЕ отбрасываются (LNB-25/FR-UI-257).

use crate::neko_bean::profile_from_bean;
use crate::util::{decode_b64_any, LinkError, Result};
use serde::Deserialize;

/// JSON bean NekoBox (ключи fmt/*Bean.hpp; пустые значения не пишутся).
#[derive(Debug, Default, Deserialize)]
pub(crate) struct NekoBean {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub port: i64,
    #[serde(default, rename = "c_cfg")]
    pub c_cfg: String,
    #[serde(default, rename = "c_out")]
    pub c_out: String,
    /// 5 socks5 | 4 socks4 | -80 http.
    #[serde(default, rename = "v")]
    pub socks_type: i64,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub pass: String,
    #[serde(default)]
    pub plugin: String,
    #[serde(default)]
    pub uot: i64,
    #[serde(default, rename = "id")]
    pub vmess_id: String,
    #[serde(default)]
    pub aid: i64,
    #[serde(default)]
    pub sec: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default, rename = "obfsPassword")]
    pub obfs_password: String,
    #[serde(default, rename = "uploadMbps")]
    pub upload_mbps: i64,
    #[serde(default, rename = "downloadMbps")]
    pub download_mbps: i64,
    #[serde(default, rename = "hopInterval")]
    pub hop_interval_sec: i64,
    #[serde(default, rename = "hopPort")]
    pub hop_port: String,
    #[serde(default, rename = "uuid")]
    pub tuic_uuid: String,
    #[serde(default, rename = "congestionControl")]
    pub congestion: String,
    #[serde(default, rename = "udpRelayMode")]
    pub udp_relay_mode: String,
    #[serde(default, rename = "zeroRttHandshake")]
    pub zero_rtt: bool,
    #[serde(default)]
    pub heartbeat: String,
    #[serde(default)]
    pub uos: bool,
    #[serde(default, rename = "allowInsecure")]
    pub allow_insecure: bool,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub alpn: String,
    #[serde(default, rename = "caText")]
    pub ca_text: String,
    #[serde(default, rename = "disableSni")]
    pub disable_sni: bool,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub extra_headers: String,
    #[serde(default)]
    pub certificate: String,
    #[serde(default)]
    pub insecure_concurrency: i64,
    #[serde(default)]
    pub disable_log: bool,
    #[serde(default)]
    pub core: String,
    #[serde(default, rename = "cmd")]
    pub command: Vec<String>,
    #[serde(default, rename = "cs")]
    pub config_simple: String,
    #[serde(default, rename = "cs_suffix")]
    pub config_suffix: String,
    #[serde(default)]
    pub mapping_port: i64,
    #[serde(default)]
    pub socks_port: i64,
    #[serde(default)]
    pub list: Vec<i64>,
    #[serde(default)]
    pub stream: Option<NekoStream>,
}

/// V2rayStreamSettings (ключи fmt/V2RayStreamSettings.hpp).
#[derive(Debug, Default, Deserialize)]
pub(crate) struct NekoStream {
    #[serde(default, rename = "net")]
    pub network: String,
    #[serde(default, rename = "sec")]
    pub security: String,
    #[serde(default, rename = "pac_enc")]
    pub packet_encoding: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default, rename = "h_type")]
    pub header_type: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub alpn: String,
    #[serde(default, rename = "cert")]
    pub certificate: String,
    #[serde(default)]
    pub utls: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, rename = "ed_name")]
    pub ed_name: String,
    #[serde(default, rename = "ed_len")]
    pub ed_len: i64,
    #[serde(default)]
    pub pbk: String,
    #[serde(default)]
    pub sid: String,
    #[serde(default)]
    pub spx: String,
    #[serde(default, rename = "mux_s")]
    pub mux_s: i64,
}

/// Разобрать nekoray://<type>#<base64url(JSON bean)>.
pub fn parse_neko_link(s: &str) -> Result<lavray_model::Profile> {
    let body = &s["nekoray://".len()..];
    let Some((typ, b64)) = body.split_once('#') else {
        return Err(LinkError(
            "nekoray: ожидается формат nekoray://<тип>#<base64 bean>".into(),
        ));
    };
    let typ = typ.to_lowercase();
    if typ.is_empty() || b64.trim().is_empty() {
        return Err(LinkError(
            "nekoray: ожидается формат nekoray://<тип>#<base64 bean>".into(),
        ));
    }
    let raw = decode_b64_any(b64)
        .ok_or_else(|| LinkError("nekoray: некорректный base64 в bean".into()))?;
    let mut bean: NekoBean = serde_json::from_slice(&raw)
        .map_err(|e| LinkError(format!("nekoray: bean не является корректным JSON: {e}")))?;
    // LNB-25/FR-UI-257: конфиг ядра из ссылки не доставляется.
    bean.c_cfg = String::new();
    bean.c_out = String::new();
    profile_from_bean(&typ, &bean)
}
