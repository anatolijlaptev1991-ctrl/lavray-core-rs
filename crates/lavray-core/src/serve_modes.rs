// SPDX-License-Identifier: GPL-3.0-only

//! Дополнительные режимы serve: gateway (redirect TCP / UDP tproxy)
//! и tun — задачи поверх outbound активного профиля.

use std::sync::Arc;

/// Дополнительные режимы serve (gateway/tun).
#[derive(Default)]
pub struct ServeModes {
    /// Redirect-inbound (TCP) — Linux.
    pub gateway: Option<String>,
    /// UDP tproxy-inbound — Linux.
    pub gateway_udp: Option<String>,
    /// TUN-интерфейс (адаптер wintun/udev) — требует админ-прав.
    pub tun: Option<String>,
}

/// Запустить gateway/tun-задачи (каждая самостоятельная; ошибка — в лог).
pub fn spawn_modes(
    modes: &ServeModes,
    outbound: &Arc<lavray_engine::Outbound>,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) {
    // macOS/прочие Unix: все режимы linux/windows-only — параметры
    // израсходованы, чтобы не было unused (clippy -D warnings).
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let _ = (&outbound, shutdown_rx);
    #[cfg(target_os = "linux")]
    if let Some(listen) = &modes.gateway {
        let cfg = lavray_engine::redirect_inbound::RedirectConfig {
            listen: match listen.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("lavray-core: --gateway {listen}: {e}");
                    return;
                }
            },
            outbound: (**outbound).clone(),
        };
        let rx = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = lavray_engine::redirect_inbound::run(cfg, rx).await {
                eprintln!("lavray-core: gateway: {e}");
            }
        });
        eprintln!("lavray-core: gateway redirect on {listen}");
    }
    #[cfg(target_os = "linux")]
    if let Some(listen) = &modes.gateway_udp {
        let cfg = lavray_engine::udp_tproxy::UdpTproxyConfig {
            listen: match listen.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("lavray-core: --gateway-udp {listen}: {e}");
                    return;
                }
            },
            outbound: (**outbound).clone(),
            nat_ttl: std::time::Duration::from_secs(60),
        };
        let rx = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = lavray_engine::udp_tproxy_run::run(cfg, rx).await {
                eprintln!("lavray-core: gateway-udp: {e}");
            }
        });
        eprintln!("lavray-core: gateway udp tproxy on {listen}");
    }
    if let Some(name) = &modes.tun {
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        eprintln!("lavray-core: --tun {name}: платформа без TUN-поддержки (linux/windows)");
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            let tun_dev = match lavray_engine::tun_device::TunDevice::open(name) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("lavray-core: --tun {name}: {e} (нужны админ-права)");
                    return;
                }
            };
            let tun_io: Box<dyn lavray_engine::netstack_types::TunIo> = Box::new(tun_dev);
            let cfg = lavray_engine::tun_proxy::TunProxyConfig {
                address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 19, 0, 1)),
                prefix: 32,
                outbound: (**outbound).clone(),
            };
            let rx = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(e) = lavray_engine::tun_proxy::run(cfg, tun_io, rx).await {
                    eprintln!("lavray-core: tun: {e}");
                }
            });
            eprintln!("lavray-core: tun [{name}] запущен (SYN-перехват всех портов)");
        }
    }
}

/// Разобрать флаги serve; ошибка — сообщение (код 2).
pub fn parse_args(args: &[String]) -> Result<(String, String, ServeModes), String> {
    let mut listen = String::new();
    let mut data = default_data_dir();
    let mut modes = ServeModes::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let value = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{arg} требует значение"))
        };
        match arg {
            "--listen-socket" => listen = value(&mut i)?,
            "--data" => data = value(&mut i)?,
            "--gateway" => modes.gateway = Some(value(&mut i)?),
            "--gateway-udp" => modes.gateway_udp = Some(value(&mut i)?),
            "--tun" => modes.tun = Some(value(&mut i)?),
            other => return Err(format!("неизвестный флаг {other:?}")),
        }
        i += 1;
    }
    if listen.is_empty() {
        return Err("--listen-socket обязателен".into());
    }
    Ok((listen, data, modes))
}

/// Каталог данных по умолчанию: ./data рядом с бинарём.
fn default_data_dir() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|d| d.join("data").to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "data".into())
}
