// SPDX-License-Identifier: GPL-3.0-only

//! Маппинг nekoBean → Profile (порт Go `links/neko.go` profileFromBean).
//! Построение Detail по типам — в neko_detail.rs. Вынесено из neko.rs ради
//! трещотки размеров.

use crate::caps::{NETWORKS, UTLS_FPS};
use crate::neko::{NekoBean, NekoStream};
use crate::neko_detail::build_detail;
use crate::stream::validate_stream_caps;
use crate::util::{check_field_len, LinkError, Result, MAX_REMARK_LENGTH};
use lavray_model::{Profile, StreamSettings};

fn stream_from_neko(ns: &NekoStream) -> StreamSettings {
    let mut st = StreamSettings {
        network: ns.network.clone(),
        header_type: ns.header_type.clone(),
        path: ns.path.clone(),
        host: ns.host.clone(),
        ws_early_data_header: ns.ed_name.clone(),
        ws_early_data_max: ns.ed_len,
        security: ns.security.clone(),
        sni: ns.sni.clone(),
        alpn: ns.alpn.clone(),
        allow_insecure: ns.insecure,
        certificate: ns.certificate.clone(),
        utls_fingerprint: ns.utls.clone(),
        reality_public_key: ns.pbk.clone(),
        reality_short_id: ns.sid.clone(),
        reality_spx: ns.spx.clone(),
        packet_encoding: ns.packet_encoding.clone(),
        multiplex: ns.mux_s,
        ..Default::default()
    };
    if st.network == "h2" {
        st.network = "http".into();
    }
    st
}

/// Разобрать bean в профиль по строковому типу (host-часть nekoray://<type>).
pub(crate) fn profile_from_bean(typ: &str, b: &NekoBean) -> Result<Profile> {
    let (ptype, detail, need_addr_port) = build_detail(typ, b)?;
    let mut p = Profile {
        r#type: ptype,
        name: b.name.clone(),
        address: b.addr.trim().to_string(),
        port: b.port,
        detail: Some(detail),
        ..Default::default()
    };
    if let Some(ns) = &b.stream {
        p.stream = Some(stream_from_neko(ns));
    }
    validate_neko_stream(&mut p)?;
    if need_addr_port {
        if p.address.is_empty() {
            return Err(LinkError("nekoray: не указан адрес сервера".into()));
        }
        if !(1..=65535).contains(&p.port) {
            return Err(LinkError(format!(
                "nekoray: порт {} вне диапазона 1–65535",
                p.port
            )));
        }
    }
    check_field_len("имя", &p.name, MAX_REMARK_LENGTH)?;
    Ok(p)
}

fn validate_neko_stream(p: &mut Profile) -> Result<()> {
    let Some(st) = p.stream.as_mut() else {
        return Ok(());
    };
    if !st.network.is_empty() && !NETWORKS.contains(&st.network.as_str()) {
        return Err(LinkError(format!(
            "nekoray: сеть {:?} не поддерживается",
            st.network
        )));
    }
    if !matches!(st.security.as_str(), "" | "tls" | "reality") {
        return Err(LinkError(format!(
            "nekoray: security {:?} не поддерживается",
            st.security
        )));
    }
    if !st.utls_fingerprint.is_empty() && !UTLS_FPS.contains(&st.utls_fingerprint.as_str()) {
        return Err(LinkError(format!(
            "nekoray: отпечаток uTLS {:?} не поддерживается",
            st.utls_fingerprint
        )));
    }
    if !st.reality_public_key.is_empty() {
        st.security = "reality".into();
    }
    validate_stream_caps(st)
}
