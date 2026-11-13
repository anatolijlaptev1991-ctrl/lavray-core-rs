// SPDX-License-Identifier: GPL-3.0-only

//! Конверсии Detail QUIC/custom model ↔ proto (волна 6). Вынесено из
//! profile_detail.rs ради трещотки размеров.

use lavray_model::{self as m, ProfileType};
use lavray_proto::v1 as pb;

fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}
fn opt_i32(v: i64) -> Option<i32> {
    if v == 0 {
        None
    } else {
        Some(i32::try_from(v).unwrap_or(i32::MAX))
    }
}

// ---- hysteria2 ----
pub(crate) fn hysteria2_to_proto(d: &m::Hysteria2Detail) -> pb::Hysteria2Detail {
    pb::Hysteria2Detail {
        password: opt(&d.password),
        obfs_password: opt(&d.obfs_password),
        upload_mbps: opt_i32(d.upload_mbps),
        download_mbps: opt_i32(d.download_mbps),
        server_ports: opt(&d.server_ports),
        hop_interval: opt(&d.hop_interval),
        sni: opt(&d.sni),
        ca: opt(&d.ca),
        allow_insecure: Some(d.allow_insecure),
        disable_sni: Some(d.disable_sni),
    }
}

pub(crate) fn hysteria2_from_proto(d: &pb::Hysteria2Detail) -> m::Hysteria2Detail {
    m::Hysteria2Detail {
        password: d.password.clone().unwrap_or_default(),
        obfs_password: d.obfs_password.clone().unwrap_or_default(),
        upload_mbps: d.upload_mbps.map_or(0, i64::from),
        download_mbps: d.download_mbps.map_or(0, i64::from),
        server_ports: d.server_ports.clone().unwrap_or_default(),
        hop_interval: d.hop_interval.clone().unwrap_or_default(),
        sni: d.sni.clone().unwrap_or_default(),
        ca: d.ca.clone().unwrap_or_default(),
        allow_insecure: d.allow_insecure.unwrap_or(false),
        disable_sni: d.disable_sni.unwrap_or(false),
        ..Default::default()
    }
}

// ---- tuic ----
pub(crate) fn tuic_to_proto(d: &m::TuicDetail) -> pb::TuicDetail {
    use pb::tuic_detail::{CongestionControl, UdpRelayMode};
    let cc = match d.congestion_control.as_str() {
        "bbr" => CongestionControl::Bbr,
        "cubic" => CongestionControl::Cubic,
        "new_reno" => CongestionControl::NewReno,
        _ => CongestionControl::Unspecified,
    };
    let urm = match d.udp_relay_mode.as_str() {
        "native" => UdpRelayMode::Native,
        "quic" => UdpRelayMode::Quic,
        _ => UdpRelayMode::Unspecified,
    };
    pb::TuicDetail {
        uuid: d.uuid.clone(),
        password: opt(&d.password),
        congestion_control: cc as i32,
        udp_relay_mode: urm as i32,
        zero_rtt_handshake: Some(d.zero_rtt_handshake),
        heartbeat: opt(&d.heartbeat),
        sni: opt(&d.sni),
        alpn: opt(&d.alpn),
        ca: opt(&d.ca),
        allow_insecure: Some(d.allow_insecure),
        disable_sni: Some(d.disable_sni),
        udp_over_stream: Some(d.udp_over_stream),
    }
}

pub(crate) fn tuic_from_proto(d: &pb::TuicDetail) -> m::TuicDetail {
    use pb::tuic_detail::{CongestionControl, UdpRelayMode};
    let cc = match CongestionControl::try_from(d.congestion_control)
        .unwrap_or(CongestionControl::Unspecified)
    {
        CongestionControl::Unspecified => "",
        CongestionControl::Bbr => "bbr",
        CongestionControl::Cubic => "cubic",
        CongestionControl::NewReno => "new_reno",
    };
    let urm = match UdpRelayMode::try_from(d.udp_relay_mode).unwrap_or(UdpRelayMode::Unspecified) {
        UdpRelayMode::Unspecified => "",
        UdpRelayMode::Native => "native",
        UdpRelayMode::Quic => "quic",
    };
    m::TuicDetail {
        uuid: d.uuid.clone(),
        password: d.password.clone().unwrap_or_default(),
        congestion_control: cc.to_string(),
        udp_relay_mode: urm.to_string(),
        zero_rtt_handshake: d.zero_rtt_handshake.unwrap_or(false),
        heartbeat: d.heartbeat.clone().unwrap_or_default(),
        sni: d.sni.clone().unwrap_or_default(),
        alpn: d.alpn.clone().unwrap_or_default(),
        ca: d.ca.clone().unwrap_or_default(),
        allow_insecure: d.allow_insecure.unwrap_or(false),
        disable_sni: d.disable_sni.unwrap_or(false),
        udp_over_stream: d.udp_over_stream.unwrap_or(false),
    }
}

// ---- custom ----
pub(crate) fn custom_to_proto(t: ProfileType, d: &m::CustomDetail) -> pb::CustomDetail {
    use pb::custom_detail::Core;
    let core = match t {
        ProfileType::CustomOutbound => Core::Internal,
        ProfileType::CustomConfig => Core::InternalFull,
        _ => Core::External,
    };
    pb::CustomDetail {
        core: core as i32,
        external_core_name: opt(&d.external_core_name),
        command: opt(&d.command.join(" ")),
        config_suffix: opt(&d.config_suffix),
        config_template: opt(&d.config_template),
        mapping_port: opt_i32(d.mapping_port),
        socks_port: opt_i32(d.socks_port),
        outbound_json: opt(&d.outbound_json),
        full_config_json: opt(&d.full_config_json),
    }
}

pub(crate) fn custom_from_proto(t: ProfileType, d: &pb::CustomDetail) -> m::CustomDetail {
    use pb::custom_detail::Core;
    let core = match Core::try_from(d.core).unwrap_or(Core::Unspecified) {
        Core::Internal => "internal",
        Core::InternalFull => "internal-full",
        _ => "external",
    };
    let _ = t;
    m::CustomDetail {
        core: core.to_string(),
        external_core_name: d.external_core_name.clone().unwrap_or_default(),
        command: d
            .command
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
        config_suffix: d.config_suffix.clone().unwrap_or_default(),
        config_template: d.config_template.clone().unwrap_or_default(),
        mapping_port: d.mapping_port.map_or(0, i64::from),
        socks_port: d.socks_port.map_or(0, i64::from),
        outbound_json: d.outbound_json.clone().unwrap_or_default(),
        full_config_json: d.full_config_json.clone().unwrap_or_default(),
    }
}
