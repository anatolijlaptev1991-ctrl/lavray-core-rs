// SPDX-License-Identifier: GPL-3.0-only

//! Построение Detail из nekoBean для QUIC/custom типов (порт Go `links/neko.go`
//! profileFromBean). Вынесено из neko_detail.rs ради трещотки размеров.

use crate::caps::{validate_duration, validate_server_ports, TUIC_CONGESTIONS, TUIC_RELAY_MODES};
use crate::neko::NekoBean;
use crate::util::{LinkError, Result};
use lavray_model::{CustomDetail, Detail, Hysteria2Detail, ProfileType, TuicDetail};

pub(crate) fn hysteria2(b: &NekoBean) -> Result<(ProfileType, Detail, bool)> {
    if b.password.is_empty() {
        return Err(LinkError("nekoray: hysteria2-пароль пуст".into()));
    }
    validate_server_ports(&b.hop_port)?;
    let hop = if b.hop_interval_sec > 0 {
        format!("{}s", b.hop_interval_sec)
    } else {
        String::new()
    };
    let d = Hysteria2Detail {
        password: b.password.clone(),
        obfs_password: b.obfs_password.clone(),
        upload_mbps: b.upload_mbps,
        download_mbps: b.download_mbps,
        server_ports: b.hop_port.clone(),
        hop_interval: hop,
        sni: b.sni.clone(),
        alpn: b.alpn.clone(),
        ca: b.ca_text.clone(),
        allow_insecure: b.allow_insecure,
        disable_sni: b.disable_sni,
    };
    Ok((ProfileType::Hysteria2, Detail::Hysteria2(d), true))
}

pub(crate) fn tuic(b: &NekoBean) -> Result<(ProfileType, Detail, bool)> {
    if !TUIC_CONGESTIONS.contains(&b.congestion.as_str()) {
        return Err(LinkError(format!(
            "nekoray: tuic congestion_control {:?} не поддерживается",
            b.congestion
        )));
    }
    if !TUIC_RELAY_MODES.contains(&b.udp_relay_mode.as_str()) {
        return Err(LinkError(format!(
            "nekoray: tuic udp_relay_mode {:?} не поддерживается",
            b.udp_relay_mode
        )));
    }
    if b.tuic_uuid.is_empty() || b.password.is_empty() {
        return Err(LinkError("nekoray: tuic uuid/пароль пуст".into()));
    }
    if !b.heartbeat.is_empty() {
        validate_duration("heartbeat", &b.heartbeat)?;
    }
    let d = TuicDetail {
        uuid: b.tuic_uuid.clone(),
        password: b.password.clone(),
        congestion_control: b.congestion.clone(),
        udp_relay_mode: b.udp_relay_mode.clone(),
        zero_rtt_handshake: b.zero_rtt,
        heartbeat: b.heartbeat.clone(),
        sni: b.sni.clone(),
        alpn: b.alpn.clone(),
        ca: b.ca_text.clone(),
        allow_insecure: b.allow_insecure,
        disable_sni: b.disable_sni,
        udp_over_stream: b.uos,
    };
    Ok((ProfileType::Tuic, Detail::Tuic(d), true))
}

pub(crate) fn custom(b: &NekoBean) -> (ProfileType, Detail, bool) {
    let mut d = CustomDetail {
        command: b.command.clone(),
        config_suffix: b.config_suffix.clone(),
        mapping_port: b.mapping_port,
        socks_port: b.socks_port,
        ..Default::default()
    };
    let pt = match b.core.as_str() {
        "internal" => {
            d.core = "internal".into();
            d.outbound_json.clone_from(&b.config_simple);
            ProfileType::CustomOutbound
        }
        "internal-full" => {
            d.core = "internal-full".into();
            d.full_config_json.clone_from(&b.config_simple);
            ProfileType::CustomConfig
        }
        _ => {
            d.core = "external".into();
            d.external_core_name.clone_from(&b.core);
            d.config_template.clone_from(&b.config_simple);
            ProfileType::CustomExternal
        }
    };
    (pt, Detail::Custom(d), false)
}
