// SPDX-License-Identifier: GPL-3.0-only

//! Конверсии Profile model ↔ proto (волна 6). Detail — в profile_detail.rs,
//! Stream — в profile_stream.rs. custom_fields_confirmed и unsupported_reason —
//! только чтение (T-08B), вычисляются ядром, значение от клиента игнорируется.

use crate::profile_detail::{detail_from_proto, detail_to_proto};
use crate::profile_stream::{stream_from_proto, stream_to_proto};
use lavray_model::{self as m, Profile, ProfileType, TestResult, TrafficCounters};
use lavray_proto::v1 as pb;

/// model ProfileType → proto ProfileType.
#[must_use]
pub fn profile_type_to_proto(t: ProfileType) -> pb::ProfileType {
    match t {
        ProfileType::Socks => pb::ProfileType::Socks,
        ProfileType::Http => pb::ProfileType::Http,
        ProfileType::Shadowsocks => pb::ProfileType::Shadowsocks,
        ProfileType::Trojan => pb::ProfileType::Trojan,
        ProfileType::VMess => pb::ProfileType::Vmess,
        ProfileType::Vless => pb::ProfileType::Vless,
        ProfileType::Naive => pb::ProfileType::Naive,
        ProfileType::Hysteria2 => pb::ProfileType::Hysteria2,
        ProfileType::Tuic => pb::ProfileType::Tuic,
        ProfileType::CustomOutbound => pb::ProfileType::CustomOutbound,
        ProfileType::CustomConfig => pb::ProfileType::CustomConfig,
        ProfileType::CustomExternal => pb::ProfileType::CustomExternal,
        ProfileType::Chain => pb::ProfileType::Chain,
    }
}

/// proto ProfileType → model ProfileType (Unspecified → Socks, валидируется выше).
#[must_use]
pub fn profile_type_from_proto(t: i32) -> ProfileType {
    match pb::ProfileType::try_from(t).unwrap_or(pb::ProfileType::Unspecified) {
        pb::ProfileType::Http => ProfileType::Http,
        pb::ProfileType::Shadowsocks => ProfileType::Shadowsocks,
        pb::ProfileType::Trojan => ProfileType::Trojan,
        pb::ProfileType::Vmess => ProfileType::VMess,
        pb::ProfileType::Vless => ProfileType::Vless,
        pb::ProfileType::Naive => ProfileType::Naive,
        pb::ProfileType::Hysteria2 => ProfileType::Hysteria2,
        pb::ProfileType::Tuic => ProfileType::Tuic,
        pb::ProfileType::CustomOutbound => ProfileType::CustomOutbound,
        pb::ProfileType::CustomConfig => ProfileType::CustomConfig,
        pb::ProfileType::CustomExternal => ProfileType::CustomExternal,
        pb::ProfileType::Chain => ProfileType::Chain,
        _ => ProfileType::Socks,
    }
}

fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// model TestResult → proto TestResult (full_report JSON-строка → FullTestReport).
#[must_use]
pub fn test_result_to_proto(r: &TestResult) -> pb::TestResult {
    pb::TestResult {
        latency_ms: r.latency_ms,
        full_report: full_report_from_json(&r.full_report),
        tested_at_ms: r.tested_at_ms,
        last_error: opt(&r.last_error),
    }
}

/// proto TestResult → model TestResult.
#[must_use]
pub fn test_result_from_proto(r: &pb::TestResult) -> TestResult {
    TestResult {
        latency_ms: r.latency_ms,
        full_report: full_report_to_json(r.full_report.as_ref()),
        tested_at_ms: r.tested_at_ms,
        last_error: r.last_error.clone().unwrap_or_default(),
    }
}

fn full_report_from_json(s: &str) -> Option<pb::FullTestReport> {
    if s.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(s).ok()?;
    let as_i32 = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_i64)
            .and_then(|x| i32::try_from(x).ok())
    };
    Some(pb::FullTestReport {
        latency_ms: as_i32("latency_ms"),
        udp_latency_ms: as_i32("udp_latency_ms"),
        download_bps: v.get("download_bps").and_then(serde_json::Value::as_f64),
        ingress_ip: v
            .get("ingress_ip")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        egress_ip: v
            .get("egress_ip")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        error: v
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    })
}

fn full_report_to_json(r: Option<&pb::FullTestReport>) -> String {
    let Some(r) = r else { return String::new() };
    serde_json::json!({
        "latency_ms": r.latency_ms, "udp_latency_ms": r.udp_latency_ms,
        "download_bps": r.download_bps, "ingress_ip": r.ingress_ip,
        "egress_ip": r.egress_ip, "error": r.error,
    })
    .to_string()
}

/// model Profile → proto Profile.
#[must_use]
pub fn profile_to_proto(p: &Profile) -> pb::Profile {
    pb::Profile {
        id: p.id,
        group_id: p.group_id,
        r#type: profile_type_to_proto(p.r#type) as i32,
        name: p.name.clone(),
        address: p.address.clone(),
        port: i32::try_from(p.port).unwrap_or(0),
        test_result: Some(test_result_to_proto(&p.test_result)),
        traffic: Some(pb::TrafficCounters {
            uplink_bytes: p.traffic.uplink_bytes,
            downlink_bytes: p.traffic.downlink_bytes,
            last_update_ms: None,
        }),
        favorite: p.favorite,
        tags: p.tags.clone(),
        notes: opt(&p.notes),
        created_at_ms: Some(p.created_at_ms),
        updated_at_ms: Some(p.updated_at_ms),
        custom_outbound_json: opt(&p.custom_outbound_json),
        custom_config_json: opt(&p.custom_config_json),
        custom_fields_confirmed: m::custom_confirmed(p),
        stream: p.stream.as_ref().map(stream_to_proto),
        detail: p.detail.as_ref().map(|d| detail_to_proto(p.r#type, d)),
        geo: p.geo.clone(),
        unsupported_reason: lavray_cfgbuild::validate::unsupported_reason(p),
    }
}

/// proto Profile → model Profile (клиентские custom_fields_confirmed/
/// unsupported_reason игнорируются; custom_hash не принимается от клиента).
#[must_use]
pub fn profile_from_proto(p: &pb::Profile) -> Profile {
    let ptype = profile_type_from_proto(p.r#type);
    Profile {
        id: p.id,
        group_id: p.group_id,
        r#type: ptype,
        name: p.name.clone(),
        address: p.address.clone(),
        port: i64::from(p.port),
        favorite: p.favorite,
        tags: p.tags.clone(),
        notes: p.notes.clone().unwrap_or_default(),
        geo: p.geo.clone(),
        test_result: p
            .test_result
            .as_ref()
            .map(test_result_from_proto)
            .unwrap_or_default(),
        traffic: p
            .traffic
            .as_ref()
            .map_or(TrafficCounters::default(), |t| TrafficCounters {
                uplink_bytes: t.uplink_bytes,
                downlink_bytes: t.downlink_bytes,
            }),
        custom_outbound_json: p.custom_outbound_json.clone().unwrap_or_default(),
        custom_config_json: p.custom_config_json.clone().unwrap_or_default(),
        custom_fields_confirmed: false,
        custom_hash: String::new(),
        stream: p.stream.as_ref().map(stream_from_proto),
        detail: p.detail.as_ref().map(|d| detail_from_proto(ptype, d)),
        created_at_ms: p.created_at_ms.unwrap_or(0),
        updated_at_ms: p.updated_at_ms.unwrap_or(0),
        ..Default::default()
    }
}
