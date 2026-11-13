// SPDX-License-Identifier: GPL-3.0-only

//! Построение Detail из nekoBean по типам (порт Go `links/neko.go`
//! profileFromBean, switch по типу). Вынесено из neko_bean.rs ради трещотки
//! размеров и clippy::too_many_lines. Каждая функция мала и самодостаточна.

use crate::caps::{SS_METHODS, VLESS_FLOWS, VMESS_SECURITIES};
use crate::neko::NekoBean;
use crate::neko_detail_quic::{custom, hysteria2, tuic};
use crate::util::{LinkError, Result};
use lavray_model::{
    ChainDetail, Detail, NaiveDetail, ProfileType, ShadowsocksDetail, SocksHttpDetail,
    TrojanVlessDetail, VMessDetail,
};

/// (тип, Detail, need_addr_port) для строкового типа nekoray://<type>.
pub(crate) fn build_detail(typ: &str, b: &NekoBean) -> Result<(ProfileType, Detail, bool)> {
    match typ {
        "socks" | "http" => Ok(socks_http(typ, b)),
        "shadowsocks" => shadowsocks(b),
        "vmess" => vmess(b),
        "trojan" | "vless" => trojan_vless(typ, b),
        "naive" => Ok((ProfileType::Naive, Detail::Naive(naive(b)), true)),
        "hysteria2" => hysteria2(b),
        "tuic" => tuic(b),
        "custom" => Ok(custom(b)),
        "chain" => Ok((
            ProfileType::Chain,
            Detail::Chain(ChainDetail {
                profile_ids: b.list.clone(),
            }),
            false,
        )),
        _ => Err(LinkError(format!(
            "nekoray: неизвестный тип профиля {typ:?}"
        ))),
    }
}

fn socks_http(typ: &str, b: &NekoBean) -> (ProfileType, Detail, bool) {
    let mut proto = "socks5";
    let mut pt = ProfileType::Socks;
    if typ == "http" {
        pt = ProfileType::Http;
        proto = "http";
    } else if b.socks_type == 4 {
        proto = "socks4";
    }
    let d = SocksHttpDetail {
        proto: proto.into(),
        username: b.username.clone(),
        password: b.password.clone(),
    };
    (pt, Detail::SocksHttp(d), true)
}

fn shadowsocks(b: &NekoBean) -> Result<(ProfileType, Detail, bool)> {
    if !SS_METHODS.contains(&b.method.as_str()) {
        return Err(LinkError(format!(
            "nekoray: ss-метод {:?} не поддерживается",
            b.method
        )));
    }
    if b.pass.is_empty() {
        return Err(LinkError("nekoray: ss-пароль пуст".into()));
    }
    let d = ShadowsocksDetail {
        method: b.method.clone(),
        password: b.pass.clone(),
        plugin: b.plugin.clone(),
        udp_over_tcp: b.uot,
    };
    Ok((ProfileType::Shadowsocks, Detail::Shadowsocks(d), true))
}

fn vmess(b: &NekoBean) -> Result<(ProfileType, Detail, bool)> {
    if !b.sec.is_empty() && !VMESS_SECURITIES.contains(&b.sec.as_str()) {
        return Err(LinkError(format!(
            "nekoray: vmess-шифрование {:?} не поддерживается",
            b.sec
        )));
    }
    if b.vmess_id.is_empty() {
        return Err(LinkError("nekoray: vmess uuid пуст".into()));
    }
    let d = VMessDetail {
        uuid: b.vmess_id.clone(),
        alter_id: b.aid,
        security: b.sec.clone(),
    };
    Ok((ProfileType::VMess, Detail::VMess(d), true))
}

fn trojan_vless(typ: &str, b: &NekoBean) -> Result<(ProfileType, Detail, bool)> {
    let pt = if typ == "vless" {
        ProfileType::Vless
    } else {
        ProfileType::Trojan
    };
    if typ == "vless" && !b.flow.is_empty() && !VLESS_FLOWS.contains(&b.flow.as_str()) {
        return Err(LinkError(format!(
            "nekoray: vless flow {:?} не поддерживается",
            b.flow
        )));
    }
    if b.pass.is_empty() {
        return Err(LinkError(format!("nekoray: {typ}: пароль/uuid пуст")));
    }
    let d = TrojanVlessDetail {
        password: b.pass.clone(),
        flow: b.flow.clone(),
    };
    Ok((pt, Detail::TrojanVless(d), true))
}

fn naive(b: &NekoBean) -> NaiveDetail {
    NaiveDetail {
        username: b.username.clone(),
        password: b.password.clone(),
        proto: b.protocol.clone(),
        extra_headers: b.extra_headers.clone(),
        sni: b.sni.clone(),
        certificate: b.certificate.clone(),
        insecure_concurrency: b.insecure_concurrency,
        disable_logs: b.disable_log,
    }
}
