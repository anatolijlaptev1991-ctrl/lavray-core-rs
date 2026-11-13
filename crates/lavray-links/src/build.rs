// SPDX-License-Identifier: GPL-3.0-only

//! BuildLink — Bean2Link: генерация стандартной share-ссылки профиля
//! (FR-UI-190, порт Go `links/build.go`). Типы custom*/chain/naive не
//! экспортируются share-ссылкой (полное сохранение — BuildNekoLink, FR-UI-191).

use crate::build_proto::{build_socks_http, build_ss, build_trojan_vless};
use crate::build_quic::{build_hysteria2, build_tuic, build_vmess_url, build_vmess_v2rayn};
use crate::caps::{NETWORKS, UTLS_FPS};
use crate::util::{percent_encode_all, LinkError, Result, MAX_REMARK_LENGTH};
use lavray_model::{Profile, ProfileType};

/// Параметры генерации ссылок.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// false — vmess:// v2rayN (base64 JSON, FR-UI-164); true — URL XTLS #716.
    pub vmess_url_format: bool,
}

/// Сгенерировать share-ссылку профиля (паритет Go BuildLink).
pub fn build_link(p: &Profile) -> Result<String> {
    build_link_with_options(p, Options::default())
}

/// Сгенерировать share-ссылку с параметрами (паритет Go BuildLinkWithOptions).
pub fn build_link_with_options(p: &Profile, o: Options) -> Result<String> {
    match p.r#type {
        ProfileType::Naive => {
            return Err(LinkError(
                "тип naive не экспортируется share-ссылкой (внешнее ядро; используйте neko-ссылку)"
                    .into(),
            ));
        }
        ProfileType::CustomOutbound
        | ProfileType::CustomConfig
        | ProfileType::CustomExternal
        | ProfileType::Chain => {
            return Err(LinkError(
                "тип не экспортируется share-ссылкой (используйте neko-ссылку BuildNekoLink)"
                    .into(),
            ));
        }
        _ => {}
    }
    validate_for_build(p)?;
    match p.r#type {
        ProfileType::Socks | ProfileType::Http => build_socks_http(p),
        ProfileType::Shadowsocks => build_ss(p),
        ProfileType::VMess => {
            if o.vmess_url_format {
                build_vmess_url(p)
            } else {
                build_vmess_v2rayn(p)
            }
        }
        ProfileType::Vless | ProfileType::Trojan => build_trojan_vless(p),
        ProfileType::Hysteria2 => build_hysteria2(p),
        ProfileType::Tuic => build_tuic(p),
        _ => Err(LinkError("тип не поддерживается".into())),
    }
}

/// Общие проверки (LNB-15: порт 1..65535; LNB-17: списки).
fn validate_for_build(p: &Profile) -> Result<()> {
    if !(1..=65535).contains(&p.port) {
        return Err(LinkError(format!("порт {} вне диапазона 1–65535", p.port)));
    }
    if p.address.trim().is_empty() {
        return Err(LinkError("не указан адрес сервера".into()));
    }
    if p.name.len() > MAX_REMARK_LENGTH {
        return Err(LinkError(format!("имя длиннее {MAX_REMARK_LENGTH} байт")));
    }
    if let Some(st) = &p.stream {
        if !st.network.is_empty() && !NETWORKS.contains(&st.network.as_str()) {
            return Err(LinkError(format!(
                "сеть {:?} не поддерживается",
                st.network
            )));
        }
        if !matches!(st.security.as_str(), "" | "tls" | "reality") {
            return Err(LinkError(format!(
                "security {:?} не поддерживается",
                st.security
            )));
        }
        if !st.utls_fingerprint.is_empty() && !UTLS_FPS.contains(&st.utls_fingerprint.as_str()) {
            return Err(LinkError(format!(
                "отпечаток uTLS {:?} не поддерживается",
                st.utls_fingerprint
            )));
        }
        if st.security == "reality" && st.reality_public_key.is_empty() {
            return Err(LinkError(
                "security=reality требует reality_public_key (pbk)".into(),
            ));
        }
    }
    Ok(())
}

/// Ручная сборка ссылки с Qt-FullyEncoded-подобным экранированием
/// (percentEncodeAll; без «+» в query). Логин/пароль хранятся раздельно.
#[derive(Default)]
pub(crate) struct LinkBuilder {
    pub scheme: String,
    pub user: String,
    pub pass: String,
    pub has_pass: bool,
    pub host: String,
    pub port: i64,
    pub query: Vec<(String, String)>,
    pub fragment: String,
}

impl LinkBuilder {
    pub fn new(scheme: &str, p: &Profile) -> Self {
        Self {
            scheme: scheme.into(),
            host: p.address.clone(),
            port: p.port,
            fragment: p.name.clone(),
            ..Default::default()
        }
    }

    pub fn set_user(&mut self, u: &str) -> &mut Self {
        self.user = u.into();
        self.has_pass = false;
        self
    }

    pub fn set_user_pass(&mut self, u: &str, p: &str) -> &mut Self {
        self.user = u.into();
        self.pass = p.into();
        self.has_pass = true;
        self
    }

    pub fn add_q(&mut self, key: &str, value: &str) -> &mut Self {
        self.query.push((key.into(), value.into()));
        self
    }

    pub fn add_if(&mut self, key: &str, value: &str) -> &mut Self {
        if !value.is_empty() {
            self.add_q(key, value);
        }
        self
    }

    pub fn build(&self) -> String {
        let mut s = format!("{}://", self.scheme);
        if !self.user.is_empty() || self.has_pass {
            s.push_str(&percent_encode_all(&self.user));
            if self.has_pass {
                s.push(':');
                s.push_str(&percent_encode_all(&self.pass));
            }
            s.push('@');
        }
        if let Ok(ip) = self.host.parse::<std::net::IpAddr>() {
            if self.host.contains(':') {
                s.push('[');
                s.push_str(&ip.to_string());
                s.push(']');
            } else {
                s.push_str(&self.host);
            }
        } else {
            s.push_str(&self.host);
        }
        if self.port > 0 {
            s.push(':');
            s.push_str(&self.port.to_string());
        }
        if !self.query.is_empty() {
            s.push('?');
            for (i, (k, v)) in self.query.iter().enumerate() {
                if i > 0 {
                    s.push('&');
                }
                s.push_str(&percent_encode_all(k));
                s.push('=');
                s.push_str(&percent_encode_all(v));
            }
        }
        if !self.fragment.is_empty() {
            s.push('#');
            s.push_str(&percent_encode_all(&self.fragment));
        }
        s
    }
}
