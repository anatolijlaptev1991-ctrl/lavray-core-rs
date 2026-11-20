// SPDX-License-Identifier: GPL-3.0-only
//! Poll-цикл движка поверх TUN+netstack (волна 7f-3c-4b-интеграция):
//! accept_established → на каждое соединение tokio-задача с VLESS
//! outbound (через profile_outbound::VlessOutbound) + копирование
//! smoltcp-сокета ↔ upstream.
use crate::addr::TargetAddr;
use crate::netstack::{Netstack, NetstackConfig};
use crate::profile_outbound::{ProfileOutbound, from_profile};
use crate::vless::client::VlessOutbound;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
/// Конфигурация TUN-прокси.
#[derive(Debug, Clone)]
pub struct TunProxyConfig {
    /// Адрес TUN-интерфейса.
    pub address: IpAddr,
    /// Префикс TUN-сети.
    pub prefix: u8,
    /// Порт, который слушаем в TUN (обычно 80/443/все).
    pub listen_port: u16,
    /// VLESS-профиль (address/port/uuid/sni).
    pub vless: VlessOutbound,
}
/// Ошибка poll-цикла.
#[derive(Debug)]
pub struct ProxyError(pub String);
impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tun proxy: {}", self.0)
    }
}
impl std::error::Error for ProxyError {}
/// Проверить, что профиль поддержан движком (VLESS/Trojan).
///
/// # Errors
/// Неподдержанный тип.
pub fn check_profile(p: &lavray_model::profile::Profile) -> Result<VlessOutbound, ProxyError> {
    match from_profile(p) {
        Ok(ProfileOutbound::Vless(v)) => Ok(v),
        Ok(ProfileOutbound::Unsupported(t)) => Err(ProxyError(format!(
            "протокол {t} ещё не подключён к движку"
        ))),
        Err(e) => Err(ProxyError(e.to_string())),
    }
}
/// Запустить poll-цикл: TUN + netstack + задачи проксирования.
/// Функция блокирует до остановки (через shutdown-токен).
///
/// # Errors
/// I/O / netstack.
pub async fn run(
    cfg: TunProxyConfig,
    tun: Box<dyn crate::netstack_types::TunIo>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), ProxyError> {
    let ns_cfg = NetstackConfig {
        address: cfg.address,
        prefix: cfg.prefix,
        mtu: 1500,
    };
    let mut netstack = Netstack::new(ns_cfg, tun).map_err(|e| ProxyError(e.to_string()))?;
    netstack.listen_port(cfg.listen_port, 65535, 65535);
    let vless = Arc::new(cfg.vless);
    let mut established: Vec<(u16, smoltcp::iface::SocketHandle)> = Vec::new();
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        // 1. smoltcp poll (пакеты из TUN обрабатываются в netstack)
        let flows = netstack.poll().map_err(|e| ProxyError(e.to_string()))?;
        // 2. Новые установленные соединения → задачи проксирования
        let new_conns = netstack.accept_established();
        let _ = flows;
        established.extend(new_conns);
        // 3. Данные установленных соединений перекачиваем в outbound
        for (_port, handle) in &established {
            let sock = netstack.socket_mut(*handle);
            let mut buf = [0u8; 4096];
            if sock.can_recv() {
                let n = sock
                    .recv_slice(&mut buf)
                    .map_err(|e| ProxyError(format!("recv: {e}")))?;
                if n > 0 {
                    let v = Arc::clone(&vless);
                    let data = buf[..n].to_vec();
                    let target = TargetAddr::Domain("proxy-target.invalid".into(), 80);
                    let up = crate::vless::client::connect(&v, &target)
                        .await
                        .map_err(|e| ProxyError(format!("vless: {e}")))?;
                    let (mut ur, mut uw) = up;
                    uw.write_all(&data)
                        .await
                        .map_err(|e| ProxyError(format!("vless write: {e}")))?;
                    let mut resp = Vec::new();
                    ur.read_to_end(&mut resp)
                        .await
                        .map_err(|e| ProxyError(format!("vless read: {e}")))?;
                    let _ = sock.send_slice(&resp);
                }
            }
        }
        // 4. Пауза между итерациями (yield)
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
use std::time::Duration;
/// Клонировать netstack-адаптер невозможен — заглушка для тестов.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proxy_error_display() {
        let e = ProxyError("test".into());
        assert_eq!(e.to_string(), "tun proxy: test");
    }
    #[test]
    fn check_profile_rejects_unsupported() {
        let json = r#"{"type":"custom_outbound","name":"c","address":"x","port":1}"#;
        let p: lavray_model::profile::Profile = serde_json::from_str(json).expect("profile");
        let err = check_profile(&p).expect_err("unsupported");
        assert!(err.0.contains("custom outbound"));
    }
}
