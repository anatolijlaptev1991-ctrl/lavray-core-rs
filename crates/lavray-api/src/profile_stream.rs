// SPDX-License-Identifier: GPL-3.0-only

//! Конверсии StreamSettings model ↔ proto (волна 6). model хранит строки/числа,
//! proto — enum-ы (Network/Security/PacketEncoding/MultiplexStatus).

use lavray_model::StreamSettings;
use lavray_proto::v1 as pb;
use pb::stream_settings::{MultiplexStatus, Network, PacketEncoding, Security};

fn net_to_proto(s: &str) -> Network {
    match s {
        "http" => Network::Http,
        "ws" => Network::Ws,
        "grpc" => Network::Grpc,
        "httpupgrade" => Network::HttpUpgrade,
        "quic" => Network::Quic,
        "xhttp" => Network::Xhttp,
        _ => Network::Tcp, // "" / tcp
    }
}

fn net_from_proto(n: i32) -> String {
    match Network::try_from(n).unwrap_or(Network::Unspecified) {
        Network::Http => "http",
        Network::Ws => "ws",
        Network::Grpc => "grpc",
        Network::HttpUpgrade => "httpupgrade",
        Network::Quic => "quic",
        Network::Xhttp => "xhttp",
        _ => "tcp",
    }
    .to_string()
}

fn sec_to_proto(s: &str) -> Security {
    match s {
        "tls" => Security::Tls,
        "reality" => Security::Reality,
        _ => Security::None,
    }
}

fn sec_from_proto(n: i32) -> String {
    match Security::try_from(n).unwrap_or(Security::None) {
        Security::None => "",
        Security::Tls => "tls",
        Security::Reality => "reality",
    }
    .to_string()
}

fn pac_to_proto(s: &str) -> PacketEncoding {
    match s {
        "packetaddr" => PacketEncoding::PacketAddr,
        "xudp" => PacketEncoding::Xudp,
        _ => PacketEncoding::Default,
    }
}

fn pac_from_proto(n: i32) -> String {
    match PacketEncoding::try_from(n).unwrap_or(PacketEncoding::Default) {
        PacketEncoding::Default => "",
        PacketEncoding::PacketAddr => "packetaddr",
        PacketEncoding::Xudp => "xudp",
    }
    .to_string()
}

fn mux_to_proto(v: i64) -> MultiplexStatus {
    match v {
        1 => MultiplexStatus::MultiplexOn,
        2 => MultiplexStatus::MultiplexOff,
        _ => MultiplexStatus::MultiplexDefault,
    }
}

fn mux_from_proto(n: i32) -> i64 {
    match MultiplexStatus::try_from(n).unwrap_or(MultiplexStatus::MultiplexDefault) {
        MultiplexStatus::MultiplexDefault => 0,
        MultiplexStatus::MultiplexOn => 1,
        MultiplexStatus::MultiplexOff => 2,
    }
}

fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// model StreamSettings → proto StreamSettings.
#[must_use]
pub fn stream_to_proto(s: &StreamSettings) -> pb::StreamSettings {
    pb::StreamSettings {
        network: net_to_proto(&s.network) as i32,
        header_type: opt(&s.header_type),
        path: s.path.clone(),
        host: s.host.clone(),
        ws_early_data_header: opt(&s.ws_early_data_header),
        ws_early_data_max: if s.ws_early_data_max == 0 {
            None
        } else {
            Some(i32::try_from(s.ws_early_data_max).unwrap_or(i32::MAX))
        },
        security: sec_to_proto(&s.security) as i32,
        sni: s.sni.clone(),
        alpn: s.alpn.clone(),
        allow_insecure: s.allow_insecure,
        certificate: opt(&s.certificate),
        utls_fingerprint: s.utls_fingerprint.clone(),
        reality_public_key: opt(&s.reality_public_key),
        reality_short_id: opt(&s.reality_short_id),
        reality_spx: opt(&s.reality_spx),
        packet_encoding: pac_to_proto(&s.packet_encoding) as i32,
        multiplex: mux_to_proto(s.multiplex) as i32,
        xhttp_mode: s.xhttp_mode.clone(),
        xhttp_extra: s.xhttp_extra.clone(),
    }
}

/// proto StreamSettings → model StreamSettings.
#[must_use]
pub fn stream_from_proto(s: &pb::StreamSettings) -> StreamSettings {
    StreamSettings {
        network: net_from_proto(s.network),
        header_type: s.header_type.clone().unwrap_or_default(),
        path: s.path.clone(),
        host: s.host.clone(),
        ws_early_data_header: s.ws_early_data_header.clone().unwrap_or_default(),
        ws_early_data_max: s.ws_early_data_max.map_or(0, i64::from),
        security: sec_from_proto(s.security),
        sni: s.sni.clone(),
        alpn: s.alpn.clone(),
        allow_insecure: s.allow_insecure,
        certificate: s.certificate.clone().unwrap_or_default(),
        utls_fingerprint: s.utls_fingerprint.clone(),
        reality_public_key: s.reality_public_key.clone().unwrap_or_default(),
        reality_short_id: s.reality_short_id.clone().unwrap_or_default(),
        reality_spx: s.reality_spx.clone().unwrap_or_default(),
        packet_encoding: pac_from_proto(s.packet_encoding),
        multiplex: mux_from_proto(s.multiplex),
        xhttp_mode: s.xhttp_mode.clone(),
        xhttp_extra: s.xhttp_extra.clone(),
    }
}
