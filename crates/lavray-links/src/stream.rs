// SPDX-License-Identifier: GPL-3.0-only

//! Импорт StreamSettings из query ссылки (паритет Go `links/parse.go`
//! applyStreamFromQuery + stream_caps.go). Фикс P1-1: транспорт/TLS/REALITY
//! больше не теряются при импорте vless/trojan/vmess/socks-http.

use crate::caps::{
    canonical_network, normalize_alpn, normalize_security_tls, parse_bool_param, NETWORKS, UTLS_FPS,
};
use crate::util::{
    check_field_len, is_ip_addr, query_get, LinkError, Result, MAX_FIELD_LENGTH, MAX_XHTTP_EXTRA,
};
use lavray_model::StreamSettings;

/// Заполнить StreamSettings из параметров query (type/security/sni/peer/alpn/
/// fp/pbk/sid/spx/allowInsecure + сетевые). def_security — дефолт для
/// ОТСУТСТВУЮЩЕГО security (trojan/vmess-URL: "tls", vless: "").
pub fn apply_stream_from_query(
    st: &mut StreamSettings,
    pairs: &[(String, String)],
    def_security: &str,
) -> Result<()> {
    let get = |k: &str| query_get(pairs, k);

    // сеть
    let mut netw = get("type")
        .map(|v| v.trim().to_lowercase())
        .unwrap_or_default();
    if netw.is_empty() {
        netw = "tcp".into();
    }
    let netw = canonical_network(&netw);
    if !NETWORKS.contains(&netw.as_str()) {
        return Err(LinkError(format!(
            "тип транспорта {netw:?} не поддерживается (tcp, ws, grpc, http, httpupgrade, quic, xhttp)"
        )));
    }
    st.network = netw;

    // security
    let mut sec = normalize_security_tls(def_security)?;
    if let Some(v) = get("security") {
        sec = normalize_security_tls(v)?;
    }
    if let Some(v) = get("sni").filter(|v| !v.trim().is_empty()) {
        st.sni = v.trim().to_string();
    } else if let Some(v) = get("peer").filter(|v| !v.trim().is_empty()) {
        st.sni = v.trim().to_string();
    }
    if let Some(v) = get("alpn") {
        st.alpn = normalize_alpn(v);
    }
    if let Some(v) = get("allowInsecure") {
        st.allow_insecure = parse_bool_param(v);
    }
    if let Some(fp) = get("fp") {
        let fp = fp.trim();
        if !UTLS_FPS.contains(&fp) {
            return Err(LinkError(format!(
                "отпечаток uTLS {fp:?} не поддерживается"
            )));
        }
        st.utls_fingerprint = fp.to_string();
    }
    if let Some(v) = get("pbk") {
        st.reality_public_key = v.to_string();
    }
    if let Some(v) = get("sid") {
        st.reality_short_id = v.to_string();
    }
    if let Some(v) = get("spx") {
        st.reality_spx = v.to_string();
    }

    // канонизация REALITY: pbk непусто ⇒ security=reality
    st.security = if st.reality_public_key.is_empty() {
        sec
    } else {
        "reality".into()
    };

    // поля сети
    match st.network.as_str() {
        "ws" | "http" | "httpupgrade" | "xhttp" => {
            apply_xhttp_query(st, pairs);
            if let Some(v) = get("path") {
                st.path = v.to_string();
            }
            if let Some(v) = get("host") {
                st.host = if st.network == "http" {
                    v.replace('|', ",")
                } else {
                    v.to_string()
                };
            }
        }
        "grpc" => {
            if let Some(v) = get("serviceName") {
                st.path = v.to_string();
            }
        }
        "tcp" if get("headerType") == Some("http") => {
            st.header_type = "http".into();
            if let Some(v) = get("path") {
                st.path = v.to_string();
            }
            if let Some(v) = get("host") {
                st.host = v.to_string();
            }
        }
        _ => {}
    }
    Ok(())
}

/// Лимиты полей потока (LNB-17) + reality не без pbk.
pub fn validate_stream_caps(st: &StreamSettings) -> Result<()> {
    for (name, val) in [
        ("path", &st.path),
        ("host", &st.host),
        ("sni", &st.sni),
        ("alpn", &st.alpn),
        ("reality_public_key", &st.reality_public_key),
        ("reality_short_id", &st.reality_short_id),
        ("reality_spx", &st.reality_spx),
        ("header_type", &st.header_type),
        ("xhttp_mode", &st.xhttp_mode),
    ] {
        check_field_len(name, val, MAX_FIELD_LENGTH)?;
    }
    check_field_len("xhttp_extra", &st.xhttp_extra, MAX_XHTTP_EXTRA)?;
    if st.security == "reality" && st.reality_public_key.is_empty() {
        return Err(LinkError("security=reality без pbk".into()));
    }
    Ok(())
}

/// SNI из Host при IP-адресе и включённом TLS (канонизация §4.1).
pub fn sni_from_host(address: &str, st: &mut StreamSettings) {
    if st.host.is_empty() || !st.sni.is_empty() {
        return;
    }
    if st.security != "tls" && st.security != "reality" {
        return;
    }
    if is_ip_addr(address) {
        st.sni = st.host.clone();
    }
}

/// mode/extra только у XHTTP (у остальных транспортов их нет).
fn apply_xhttp_query(st: &mut StreamSettings, pairs: &[(String, String)]) {
    if st.network != "xhttp" {
        return;
    }
    st.xhttp_mode = query_get(pairs, "mode").unwrap_or("").to_string();
    st.xhttp_extra = query_get(pairs, "extra").unwrap_or("").to_string();
}
