// SPDX-License-Identifier: GPL-3.0-only

//! Конверсии Detail model ↔ proto (волна 6): oneof из 9 bean-ов. QUIC/custom —
//! в profile_detail_quic.rs. model хранит строки, proto — enum-ы (Proto/Uot).

use crate::profile_detail_quic::{
    custom_from_proto, custom_to_proto, hysteria2_from_proto, hysteria2_to_proto, tuic_from_proto,
    tuic_to_proto,
};
use lavray_model::{self as m, Detail, ProfileType};
use lavray_proto::v1 as pb;

fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// model Detail → proto oneof Detail (по типу профиля).
#[must_use]
pub fn detail_to_proto(t: ProfileType, d: &Detail) -> pb::profile::Detail {
    use pb::profile::Detail as D;
    match (t, d) {
        (_, Detail::SocksHttp(x)) => D::SocksHttp(socks_to_proto(x)),
        (_, Detail::Shadowsocks(x)) => D::Shadowsocks(ss_to_proto(x)),
        (_, Detail::VMess(x)) => D::Vmess(vmess_to_proto(x)),
        (_, Detail::TrojanVless(x)) => D::TrojanVless(tv_to_proto(x)),
        (_, Detail::Naive(x)) => D::Naive(naive_to_proto(x)),
        (_, Detail::Hysteria2(x)) => D::Hysteria2(hysteria2_to_proto(x)),
        (_, Detail::Tuic(x)) => D::Tuic(tuic_to_proto(x)),
        (_, Detail::Custom(x)) => D::Custom(custom_to_proto(t, x)),
        (_, Detail::Chain(x)) => D::Chain(pb::ChainDetail {
            profile_ids: x.profile_ids.clone(),
        }),
    }
}

/// proto oneof Detail → model Detail.
#[must_use]
pub fn detail_from_proto(t: ProfileType, d: &pb::profile::Detail) -> Detail {
    use pb::profile::Detail as D;
    match d {
        D::SocksHttp(x) => Detail::SocksHttp(socks_from_proto(x)),
        D::Shadowsocks(x) => Detail::Shadowsocks(ss_from_proto(x)),
        D::Vmess(x) => Detail::VMess(vmess_from_proto(x)),
        D::TrojanVless(x) => Detail::TrojanVless(tv_from_proto(x)),
        D::Naive(x) => Detail::Naive(naive_from_proto(x)),
        D::Hysteria2(x) => Detail::Hysteria2(hysteria2_from_proto(x)),
        D::Tuic(x) => Detail::Tuic(tuic_from_proto(x)),
        D::Custom(x) => Detail::Custom(custom_from_proto(t, x)),
        D::Chain(x) => Detail::Chain(m::ChainDetail {
            profile_ids: x.profile_ids.clone(),
        }),
    }
}

// ---- socks/http ----
fn socks_to_proto(d: &m::SocksHttpDetail) -> pb::SocksHttpDetail {
    use pb::socks_http_detail::Proto;
    let proto = match d.proto.as_str() {
        "socks4" => Proto::Socks4,
        "http" => Proto::Http,
        _ => Proto::Socks5,
    };
    pb::SocksHttpDetail {
        proto: proto as i32,
        username: opt(&d.username),
        password: opt(&d.password),
    }
}

fn socks_from_proto(d: &pb::SocksHttpDetail) -> m::SocksHttpDetail {
    use pb::socks_http_detail::Proto;
    let proto = match Proto::try_from(d.proto).unwrap_or(Proto::Unspecified) {
        Proto::Socks4 => "socks4",
        Proto::Http => "http",
        _ => "socks5",
    };
    m::SocksHttpDetail {
        proto: proto.to_string(),
        username: d.username.clone().unwrap_or_default(),
        password: d.password.clone().unwrap_or_default(),
    }
}

// ---- shadowsocks ----
fn ss_to_proto(d: &m::ShadowsocksDetail) -> pb::ShadowsocksDetail {
    use pb::shadowsocks_detail::Uot;
    let uot = match d.udp_over_tcp {
        1 => Uot::V1,
        2 => Uot::V2,
        _ => Uot::Off,
    };
    pb::ShadowsocksDetail {
        method: d.method.clone(),
        password: opt(&d.password),
        plugin: opt(&d.plugin),
        udp_over_tcp: uot as i32,
    }
}

fn ss_from_proto(d: &pb::ShadowsocksDetail) -> m::ShadowsocksDetail {
    use pb::shadowsocks_detail::Uot;
    let uot = match Uot::try_from(d.udp_over_tcp).unwrap_or(Uot::Off) {
        Uot::Off => 0,
        Uot::V1 => 1,
        Uot::V2 => 2,
    };
    m::ShadowsocksDetail {
        method: d.method.clone(),
        password: d.password.clone().unwrap_or_default(),
        plugin: d.plugin.clone().unwrap_or_default(),
        udp_over_tcp: uot,
    }
}

// ---- vmess ----
fn vmess_to_proto(d: &m::VMessDetail) -> pb::VmessDetail {
    pb::VmessDetail {
        uuid: d.uuid.clone(),
        alter_id: i32::try_from(d.alter_id).unwrap_or(i32::MAX),
        security: d.security.clone(),
    }
}

fn vmess_from_proto(d: &pb::VmessDetail) -> m::VMessDetail {
    m::VMessDetail {
        uuid: d.uuid.clone(),
        alter_id: i64::from(d.alter_id),
        security: d.security.clone(),
    }
}

// ---- trojan/vless ----
fn tv_to_proto(d: &m::TrojanVlessDetail) -> pb::TrojanVlessDetail {
    pb::TrojanVlessDetail {
        password: d.password.clone(),
        flow: opt(&d.flow),
    }
}

fn tv_from_proto(d: &pb::TrojanVlessDetail) -> m::TrojanVlessDetail {
    m::TrojanVlessDetail {
        password: d.password.clone(),
        flow: d.flow.clone().unwrap_or_default(),
    }
}

// ---- naive ----
fn naive_to_proto(d: &m::NaiveDetail) -> pb::NaiveDetail {
    use pb::naive_detail::Proto;
    let proto = if d.proto == "http" {
        Proto::Http
    } else {
        Proto::Https
    };
    pb::NaiveDetail {
        username: opt(&d.username),
        password: opt(&d.password),
        proto: proto as i32,
        extra_headers: opt(&d.extra_headers),
        sni: opt(&d.sni),
        certificate: opt(&d.certificate),
        insecure_concurrency: if d.insecure_concurrency == 0 {
            None
        } else {
            Some(i32::try_from(d.insecure_concurrency).unwrap_or(i32::MAX))
        },
        disable_logs: Some(d.disable_logs),
    }
}

fn naive_from_proto(d: &pb::NaiveDetail) -> m::NaiveDetail {
    use pb::naive_detail::Proto;
    let proto = match Proto::try_from(d.proto).unwrap_or(Proto::Unspecified) {
        Proto::Http => "http",
        _ => "https",
    };
    m::NaiveDetail {
        username: d.username.clone().unwrap_or_default(),
        password: d.password.clone().unwrap_or_default(),
        proto: proto.to_string(),
        extra_headers: d.extra_headers.clone().unwrap_or_default(),
        sni: d.sni.clone().unwrap_or_default(),
        certificate: d.certificate.clone().unwrap_or_default(),
        insecure_concurrency: d.insecure_concurrency.map_or(0, i64::from),
        disable_logs: d.disable_logs.unwrap_or(false),
    }
}
