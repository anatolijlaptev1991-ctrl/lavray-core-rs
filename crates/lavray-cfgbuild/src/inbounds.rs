// SPDX-License-Identifier: GPL-3.0-only

//! Генерация inbounds (порт Go `cfgbuild/inbounds.go` + `tproxy.go`):
//! mixed-слушатель (FR-UI-279: не-loopback требует auth), tproxy (OpenWrt),
//! TUN (FR-UI-184, kill-switch FR-UI-275), custom_inbound-добавка.

use crate::error::{Error, Result};
use crate::settings::BuildSettings;
use crate::util::{goos_of, obj, Obj};
use serde_json::{json, Value};

const TUN_IPV4: &str = "172.18.0.1/30";
const TUN_IPV6: &str = "fd4c:4156:5259::1/126";

fn default_tun_name(goos: &str) -> &'static str {
    if goos == "darwin" {
        "utun9"
    } else {
        "lavray-tun"
    }
}

/// mixed-in + tproxy-in + tun-in + custom_inbound (порт buildInbounds).
pub fn build_inbounds(st: &BuildSettings, for_test: bool) -> Result<Vec<Value>> {
    let mut inbounds: Vec<Value> = Vec::new();

    if !for_test && st.inbound.port > 0 && st.inbound.port <= 65535 {
        let mut listen = st.inbound.address.trim().to_string();
        if listen.is_empty() {
            listen = "127.0.0.1".into();
        }
        if !is_loopback_addr(&listen)
            && (st.inbound.auth_user.is_empty() || st.inbound.auth_pass.is_empty())
        {
            return Err(Error::invalid(
                "inbound.address",
                format!("non-loopback inbound address {listen:?} requires inbound.auth.user and inbound.auth.pass (FR-UI-279)"),
            ));
        }
        let mut inb = obj();
        inb.insert("tag".into(), json!("mixed-in"));
        inb.insert("type".into(), json!("mixed"));
        inb.insert("listen".into(), json!(listen));
        inb.insert("listen_port".into(), json!(st.inbound.port));
        if !st.inbound.auth_user.is_empty() && !st.inbound.auth_pass.is_empty() {
            inb.insert(
                "users".into(),
                json!([{ "username": st.inbound.auth_user, "password": st.inbound.auth_pass }]),
            );
        }
        inbounds.push(Value::Object(inb));
    }

    if let Some(tp) = tproxy_inbound(st, for_test)? {
        inbounds.push(Value::Object(tp));
    }

    if st.tun.enabled && !for_test {
        let mut name = st.tun.interface_name.trim().to_string();
        if name.is_empty() {
            name = default_tun_name(&goos_of(st)).into();
        }
        let mtu = if st.tun.mtu <= 0 { 9000 } else { st.tun.mtu };
        let mut address = vec![json!(TUN_IPV4)];
        if st.tun.ipv6 {
            address.push(json!(TUN_IPV6));
        }
        let mut inb = obj();
        inb.insert("tag".into(), json!("tun-in"));
        inb.insert("type".into(), json!("tun"));
        inb.insert("interface_name".into(), json!(name));
        inb.insert("auto_route".into(), json!(true));
        inb.insert("mtu".into(), json!(mtu));
        inb.insert("address".into(), Value::Array(address));
        let stack = st.tun.stack.trim();
        if !stack.is_empty() {
            inb.insert("stack".into(), json!(stack));
        }
        inb.insert(
            "strict_route".into(),
            json!(st.tun.strict_route || st.tun.kill_switch),
        );
        inbounds.push(Value::Object(inb));
    }

    if !for_test {
        append_custom_inbounds(st, &mut inbounds)?;
    }
    Ok(inbounds)
}

fn tproxy_inbound(st: &BuildSettings, for_test: bool) -> Result<Option<Obj>> {
    if !st.tproxy.enabled || for_test {
        return Ok(None);
    }
    if !st.openwrt {
        return Err(Error::invalid(
            "gateway.tproxy",
            "tproxy-вход доступен только в сборке для роутера (--platform openwrt); на компьютере — системный прокси или TUN",
        ));
    }
    if st.tproxy.port < 1 || st.tproxy.port > 65535 {
        return Err(Error::invalid(
            "gateway.tproxy",
            format!("порт tproxy {} вне диапазона 1–65535", st.tproxy.port),
        ));
    }
    let listen = if st.tproxy.ipv6 { "::" } else { "0.0.0.0" };
    let mut inb = obj();
    inb.insert("tag".into(), json!("tproxy-in"));
    inb.insert("type".into(), json!("tproxy"));
    inb.insert("listen".into(), json!(listen));
    inb.insert("listen_port".into(), json!(st.tproxy.port));
    Ok(Some(inb))
}

fn append_custom_inbounds(st: &BuildSettings, inbounds: &mut Vec<Value>) -> Result<()> {
    let raw = st.inbound.custom_inbound.trim();
    if raw.is_empty() || raw == "{}" {
        return Ok(());
    }
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|e| Error::invalid("inbound.custom_inbound", format!("invalid JSON: {e}")))?;
    let custom = parsed
        .get("inbounds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut used_tags: Vec<String> = inbounds
        .iter()
        .filter_map(|v| v.get("tag").and_then(Value::as_str).map(str::to_string))
        .filter(|t| !t.is_empty())
        .collect();
    for inb in custom {
        let tag = inb
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !tag.is_empty() && used_tags.contains(&tag) {
            return Err(Error::invalid(
                "inbound.custom_inbound",
                format!("тег {tag:?} уже занят сгенерированным inbound'ом"),
            ));
        }
        used_tags.push(tag);
        let listen = inb
            .get("listen")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| inb.get("listen_address").and_then(Value::as_str))
            .unwrap_or("");
        if !listen.is_empty()
            && !is_loopback_addr(listen)
            && (st.inbound.auth_user.is_empty() || st.inbound.auth_pass.is_empty())
        {
            return Err(Error::invalid(
                "inbound.custom_inbound",
                format!("inbound на {listen} требует inbound.auth.user/pass (FR-UI-279)"),
            ));
        }
        inbounds.push(inb);
    }
    Ok(())
}

/// IP-литерал loopback (127.0.0.0/8, ::1) либо имя "localhost".
fn is_loopback_addr(s: &str) -> bool {
    if s.eq_ignore_ascii_case("localhost") {
        return true;
    }
    s.trim()
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}
