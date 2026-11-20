// SPDX-License-Identifier: GPL-3.0-only

//! Мост «профиль → outbound» (интеграция движка с API): из
//! lavray-model::Profile строится типизированный исходящий туннель
//! движка. VLESS/Trojan — волна 7f; SS/VMess — уже в движке (ss/, vmess/).

use lavray_model::detail::{Detail, TrojanVlessDetail};
use lavray_model::profile::{Profile, ProfileType};
use lavray_model::stream::StreamSettings;

use crate::addr::TargetAddr;
use crate::hy2::Hy2Config;
use crate::tls::TlsDial;
use crate::tuic::TuicConfig;
use crate::vless::client::VlessOutbound;

/// Результат конвертации профиля в outbound.
#[derive(Debug)]
pub enum ProfileOutbound {
    /// VLESS-туннель (с TLS при наличии stream.tls/reality).
    Vless(VlessOutbound),
    /// TUIC v5 (QUIC) — lavray_engine::tuic::TuicConfig.
    Tuic(TuicConfig),
    /// Hysteria2 (QUIC) — lavray_engine::hy2::Hy2Config.
    Hysteria2(Hy2Config),
    /// Протокол ещё не подключён к движку.
    Unsupported(&'static str),
}

/// Ошибка конвертации.
#[derive(Debug)]
pub struct ConvertError(pub String);

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "profile→outbound: {}", self.0)
    }
}

impl std::error::Error for ConvertError {}

/// Построить outbound из профиля.
///
/// # Errors
/// Профиль не VLESS/Trojan, или обязательные поля пусты.
pub fn from_profile(p: &Profile) -> Result<ProfileOutbound, ConvertError> {
    let server = TargetAddr::Domain(
        p.address.clone(),
        u16::try_from(p.port).map_err(|_| ConvertError("port > 65535".into()))?,
    );
    match &p.r#type {
        ProfileType::Vless | ProfileType::Trojan => {
            let Some(Detail::TrojanVless(d)) = &p.detail else {
                return Ok(ProfileOutbound::Unsupported(type_name(p.r#type)));
            };
            Ok(ProfileOutbound::Vless(build_vless(
                server,
                p,
                d,
                p.r#type == ProfileType::Trojan,
            )))
        }
        ProfileType::Hysteria2 => {
            let Some(Detail::Hysteria2(d)) = &p.detail else {
                return Ok(ProfileOutbound::Unsupported(type_name(p.r#type)));
            };
            // down_mbps сервера → rx_bps клиента (Go: ReceiveBPS из ответа;
            // в клиенте rx_bps=0 → BBR по умолчанию, как при отсутствии
            // полосы в профиле).
            Ok(ProfileOutbound::Hysteria2(Hy2Config {
                server: p.address.clone(),
                server_port: u16::try_from(p.port)
                    .map_err(|_| ConvertError("port > 65535".into()))?,
                sni: stream_sni(p.stream.as_ref(), &p.address),
                password: d.password.clone(),
                rx_bps: 0,
                skip_verify: stream_insecure(p.stream.as_ref()),
            }))
        }
        ProfileType::Tuic => {
            let Some(Detail::Tuic(d)) = &p.detail else {
                return Ok(ProfileOutbound::Unsupported(type_name(p.r#type)));
            };
            Ok(ProfileOutbound::Tuic(TuicConfig {
                server: p.address.clone(),
                server_port: u16::try_from(p.port)
                    .map_err(|_| ConvertError("port > 65535".into()))?,
                sni: stream_sni(p.stream.as_ref(), &p.address),
                uuid: d.uuid.clone(),
                password: d.password.clone(),
                skip_verify: stream_insecure(p.stream.as_ref()),
            }))
        }
        t => Ok(ProfileOutbound::Unsupported(type_name(*t))),
    }
}

/// SNI из StreamSettings (fallback — адрес сервера).
fn stream_sni(stream: Option<&StreamSettings>, fallback: &str) -> String {
    let sni = stream.map_or(fallback, |s| s.sni.as_str());
    if sni.is_empty() {
        fallback.to_string()
    } else {
        sni.to_string()
    }
}

/// allow_insecure из StreamSettings.
fn stream_insecure(stream: Option<&StreamSettings>) -> bool {
    stream.is_some_and(|s| s.allow_insecure)
}

fn build_vless(
    server: TargetAddr,
    p: &Profile,
    d: &TrojanVlessDetail,
    is_trojan: bool,
) -> VlessOutbound {
    let tls = build_tls(p.stream.as_ref(), &p.address);
    let _ = is_trojan; // trojan-протокол — отдельная волна, пока vless-каркас
    VlessOutbound {
        server,
        uuid: d.password.clone(), // vless uuid хранится в password поле (Neko-формат)
        tls,
        transport: transport_of(p.stream.as_ref()),
    }
}

fn build_tls(stream: Option<&StreamSettings>, fallback_host: &str) -> Option<TlsDial> {
    let s = stream?;
    // security: "tls"/"reality" включают TLS; "none" — плоский TCP
    if s.security.is_empty() || s.security == "none" {
        return None;
    }
    Some(TlsDial {
        sni: if s.sni.is_empty() {
            fallback_host.to_string()
        } else {
            s.sni.clone()
        },
        skip_verify: s.allow_insecure,
    })
}

fn transport_of(_stream: Option<&StreamSettings>) -> crate::direct::Transport {
    // TCP по умолчанию; ws — требует dialer-фабрику (волна 7e-интеграция)
    crate::direct::Transport::Tcp
}

fn type_name(t: ProfileType) -> &'static str {
    match t {
        ProfileType::Socks => "socks",
        ProfileType::Http => "http",
        ProfileType::Shadowsocks => "shadowsocks",
        ProfileType::VMess => "vmess",
        ProfileType::Vless => "vless",
        ProfileType::Trojan => "trojan",
        ProfileType::Naive => "naive",
        ProfileType::Hysteria2 => "hysteria2",
        ProfileType::Tuic => "tuic",
        ProfileType::CustomOutbound => "custom outbound",
        ProfileType::CustomConfig => "custom config",
        ProfileType::CustomExternal => "custom external",
        ProfileType::Chain => "chain",
    }
}
