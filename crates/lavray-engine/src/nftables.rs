// SPDX-License-Identifier: GPL-3.0-only

//! Генератор nftables-правил gateway для OpenWrt: перенаправление LAN-трафика
//! (TCP, при необходимости UDP) на redirect/tproxy-порт движка с обходами
//! (серверы прокси, приватные сети, локальные порты). Golden-тест в
//! tests/nftables.rs сверяет текст с эталоном.

/// Параметры генерации nftables-конфига.
#[derive(Debug, Clone)]
pub struct NftConfig {
    /// Порт redirect-inbound движка.
    pub redirect_port: u16,
    /// Перенаправлять ли UDP (tproxy-style: только TCP если false).
    pub redirect_udp: bool,
    /// Адреса серверов прокси (исключаются из перехвата).
    pub server_ips: Vec<String>,
    /// Приватные сети-исключения (CIDR; LAN-адреса роутера/клиентов).
    pub exclude_cidrs: Vec<String>,
    /// Имя таблицы nftables.
    pub table: String,
}

impl Default for NftConfig {
    fn default() -> Self {
        Self {
            redirect_port: 7893,
            redirect_udp: false,
            server_ips: Vec::new(),
            exclude_cidrs: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "127.0.0.0/8".into(),
                "169.254.0.0/16".into(),
                "224.0.0.0/4".into(),
                "240.0.0.0/4".into(),
            ],
            table: "inet lavray".into(),
        }
    }
}

/// Сгенерировать nftables-конфиг (текст `/etc/nftables.d/lavray.nft`).
#[must_use]
pub fn generate(cfg: &NftConfig) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(1024);
    let _ = writeln!(
        out,
        "#!/usr/sbin/nft -f\n# LAVRay gateway redirect (port {})\nflush table {}\ntable {} {{",
        cfg.redirect_port, cfg.table, cfg.table
    );
    let _ = writeln!(
        out,
        "  chain prerouting {{\n    type nat hook prerouting priority dstnat; policy accept;"
    );
    for cidr in &cfg.exclude_cidrs {
        let _ = writeln!(out, "    ip daddr {cidr} return");
    }
    for ip in &cfg.server_ips {
        let _ = writeln!(out, "    ip daddr {ip} return");
    }
    let _ = writeln!(
        out,
        "    tcp daddr != 224.0.0.0/4 meta l4proto tcp redirect to :{}",
        cfg.redirect_port
    );
    if cfg.redirect_udp {
        let _ = writeln!(
            out,
            "    meta l4proto udp redirect to :{}",
            cfg.redirect_port
        );
    }
    let _ = writeln!(out, "  }}");
    let _ = writeln!(out, "}}");
    out
}

/// Итоговые shell-команды активации (OpenWrt: firewall4 грузит .nft).
#[must_use]
pub fn apply_commands(cfg: &NftConfig) -> Vec<String> {
    vec![
        "nft -f /etc/nftables.d/lavray.nft".to_string(),
        format!(
            "uci set lavray.gateway=service; uci set lavray.gateway.redirect_port='{}'; uci commit lavray",
            cfg.redirect_port
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_golden() {
        let cfg = NftConfig::default();
        let text = generate(&cfg);
        assert!(text.contains("redirect to :7893"));
        assert!(text.contains("ip daddr 192.168.0.0/16 return"));
        assert!(text.starts_with("#!/usr/sbin/nft -f"));
        assert!(text.contains("flush table inet lavray"));
    }

    #[test]
    fn server_ip_and_udp_excluded() {
        let cfg = NftConfig {
            redirect_port: 9000,
            redirect_udp: true,
            server_ips: vec!["203.0.113.10".into()],
            ..NftConfig::default()
        };
        let text = generate(&cfg);
        assert!(text.contains("ip daddr 203.0.113.10 return"));
        assert!(text.contains("redirect to :9000"));
        assert!(text.contains("meta l4proto udp redirect to :9000"));
        // порядок: исключения ДО redirect-правил
        let excl = text.find("return").expect("exclude");
        let red = text.find("redirect to").expect("redirect");
        assert!(excl < red);
    }

    #[test]
    fn apply_commands_golden() {
        let cfg = NftConfig::default();
        let cmds = apply_commands(&cfg);
        assert_eq!(cmds[0], "nft -f /etc/nftables.d/lavray.nft");
        assert!(cmds[1].contains("redirect_port='7893'"));
    }
}
