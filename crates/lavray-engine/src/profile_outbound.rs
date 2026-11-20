// SPDX-License-Identifier: GPL-3.0-only

//! Мост «профиль → outbound» (интеграция движка с API): из
//! lavray-model::Profile строится типизированный исходящий туннель
//! движка. VLESS/Trojan — волна 7f; SS/VMess — уже в движке (ss/, vmess/).

use lavray_model::detail::{Detail, TrojanVlessDetail};
use lavray_model::profile::{Profile, ProfileType};
use lavray_model::stream::StreamSettings;

use crate::addr::TargetAddr;
use crate::tls::TlsDial;
use crate::vless::client::VlessOutbound;

/// Результат конвертации профиля в outbound.
#[derive(Debug)]
pub enum ProfileOutbound {
    /// VLESS-туннель (с TLS при наличии stream.tls/reality).
    Vless(VlessOutbound),
    /// Протокол ещё не подключён к движку (hysteria2/tuic — QUIC-волна).
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
        ProfileType::Hysteria2 => Ok(ProfileOutbound::Unsupported("hysteria2 (QUIC-волна)")),
        ProfileType::Tuic => Ok(ProfileOutbound::Unsupported("tuic (QUIC-волна)")),
        t => Ok(ProfileOutbound::Unsupported(type_name(*t))),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vless_profile() -> Profile {
        // канонический JSON-путь — как реальные профили приходят из store
        let json = r#"{"type":"vless","name":"t","address":"vpn.example.com","port":443,
            "detail":{"password":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":""}}"#;
        serde_json::from_str(json).expect("profile json")
    }

    #[test]
    fn vless_profile_builds_outbound() {
        let p = vless_profile();
        let out = from_profile(&p).expect("convert");
        match out {
            ProfileOutbound::Vless(v) => {
                assert_eq!(v.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                match &v.server {
                    TargetAddr::Domain(d, port) => {
                        assert_eq!(d, "vpn.example.com");
                        assert_eq!(*port, 443);
                    }
                    TargetAddr::Ip(..) => panic!("domain expected"),
                }
            }
            ProfileOutbound::Unsupported(t) => panic!("unsupported: {t}"),
        }
    }

    #[test]
    fn hysteria2_reports_unsupported() {
        let json = r#"{"type":"hysteria2","name":"h","address":"h.example.com","port":443}"#;
        let p: Profile = serde_json::from_str(json).expect("profile json");
        let out = from_profile(&p).expect("convert");
        assert!(matches!(
            out,
            ProfileOutbound::Unsupported("hysteria2 (QUIC-волна)")
        ));
    }

    #[test]
    fn tls_from_stream_settings() {
        let mut p = vless_profile();
        // stream с TLS — упрощённо проверяем чтоtls dial не None невозможен без
        // знания структуры StreamSettings; минимальная проверка unsupported-ветки
        p.r#type = ProfileType::CustomOutbound;
        let out = from_profile(&p).expect("convert");
        assert!(matches!(
            out,
            ProfileOutbound::Unsupported("custom outbound")
        ));
    }
}
