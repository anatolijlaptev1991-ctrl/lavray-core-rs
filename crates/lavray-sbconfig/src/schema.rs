// SPDX-License-Identifier: GPL-3.0-only

//! Реестры sing-box 1.14 (extracted из эталонной JSON-схемы + Go Register):
//! inbound/outbound типы, имена Go-структур для текстов cannot unmarshal,
//! enum-значения, известные поля уровней.

/// Известные типы inbound (schema $defs/Inbound oneOf).
pub const INBOUND_TYPES: &[&str] = &[
    "anytls",
    "cloudflared",
    "direct",
    "http",
    "hysteria",
    "hysteria2",
    "mixed",
    "naive",
    "redirect",
    "shadowsocks",
    "shadowtls",
    "socks",
    "tproxy",
    "trojan",
    "tuic",
    "tun",
    "vless",
    "vmess",
];

/// Известные типы outbound (schema $defs/Outbound oneOf; dns — stub, 7f-3).
pub const OUTBOUND_TYPES: &[&str] = &[
    "anytls",
    "block",
    "bridge",
    "direct",
    "http",
    "hysteria",
    "hysteria2",
    "naive",
    "selector",
    "shadowsocks",
    "shadowtls",
    "socks",
    "ssh",
    "tor",
    "trojan",
    "tuic",
    "urltest",
    "vless",
    "vmess",
];

/// inbound type → Go-структура (для `json: cannot unmarshal … into Go struct
/// field <Struct>.<Field>`).
pub fn inbound_struct(kind: &str) -> &'static str {
    match kind {
        "mixed" | "http" => "HTTPMixedInboundOptions",
        "socks" => "SocksInboundOptions",
        "direct" => "DirectInboundOptions",
        "shadowsocks" => "ShadowsocksInboundOptions",
        "vmess" => "VMessInboundOptions",
        "vless" => "VLESSInboundOptions",
        "trojan" => "TrojanInboundOptions",
        "hysteria" => "HysteriaInboundOptions",
        "hysteria2" => "Hysteria2InboundOptions",
        "tuic" => "TUICInboundOptions",
        "tun" => "TunInboundOptions",
        "naive" => "NaiveInboundOptions",
        "shadowtls" => "ShadowTLSInboundOptions",
        "anytls" => "AnyTLSInboundOptions",
        "snell" => "SnellInboundOptions",
        "cloudflared" => "CloudflaredInboundOptions",
        "redirect" | "tproxy" => "ListenOptions",
        _ => "InboundOptions",
    }
}

/// dns.strategy enum (option.DomainStrategy).
pub const DNS_STRATEGIES: &[&str] = &["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"];

/// Известные поля верхнего уровня (option.Options, decoded-стадия).
pub const TOP_FIELDS: &[&str] = &[
    "$schema",
    "log",
    "dns",
    "ntp",
    "certificate",
    "certificate_providers",
    "http_clients",
    "network_namespaces",
    "endpoints",
    "inbounds",
    "outbounds",
    "route",
    "services",
    "experimental",
];

/// Числовые (u16) поля, чей неверный тип даёт cannot unmarshal-текст.
pub const U16_FIELDS: &[(&str, &str)] = &[
    ("listen_port", "ListenOptions.listen_port"),
    ("server_port", "DialFields.server_port"),
];
