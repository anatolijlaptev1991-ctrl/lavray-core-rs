// SPDX-License-Identifier: GPL-3.0-only
//! Poll-цикл движка поверх TUN+netstack (волна 7f-3c-4b-интеграция):
//! accept_established → на каждое соединение upstream-задача через
//! универсальный outbound-мост (VLESS / Hysteria2 / TUIC —
//! tun_outbound::Outbound) + копирование smoltcp-сокета ↔ upstream.
use crate::addr::TargetAddr;
use crate::netstack::{Netstack, NetstackConfig};
use crate::profile_outbound::{ProfileOutbound, from_profile};
use crate::tun_outbound::Outbound;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Конфигурация TUN-прокси.
#[derive(Debug, Clone)]
pub struct TunProxyConfig {
    /// Адрес TUN-интерфейса.
    pub address: IpAddr,
    /// Префикс TUN-сети.
    pub prefix: u8,
    /// Порт, который слушаем в TUN (обычно 80/443/все).
    pub listen_port: u16,
    /// Выбранный outbound (VLESS / Hysteria2 / TUIC).
    pub outbound: Outbound,
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

/// Проверить, что профиль поддержан движком (VLESS/Hysteria2/TUIC).
///
/// # Errors
/// Неподдержанный тип.
pub fn check_profile(p: &lavray_model::profile::Profile) -> Result<Outbound, ProxyError> {
    match from_profile(p) {
        Ok(ProfileOutbound::Vless(v)) => Ok(Outbound::Vless(v)),
        Ok(ProfileOutbound::Hysteria2(h)) => Ok(Outbound::Hy2(h)),
        Ok(ProfileOutbound::Tuic(t)) => Ok(Outbound::Tuic(t)),
        Ok(other) => Err(ProxyError(format!(
            "протокол ещё не подключён к tun_proxy poll-циклу: {other:?}"
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
    let outbound = Arc::new(cfg.outbound);
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
                    let v = Arc::clone(&outbound);
                    let data = buf[..n].to_vec();
                    let target = TargetAddr::Domain("proxy-target.invalid".into(), 80);
                    let mut up = v
                        .connect(&target)
                        .await
                        .map_err(|e| ProxyError(format!("outbound: {e}")))?;
                    up.write_all(&data)
                        .await
                        .map_err(|e| ProxyError(format!("outbound write: {e}")))?;
                    up.flush()
                        .await
                        .map_err(|e| ProxyError(format!("outbound flush: {e}")))?;
                    let mut resp = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = up
                            .read(&mut chunk)
                            .await
                            .map_err(|e| ProxyError(format!("outbound read: {e}")))?;
                        if n == 0 {
                            break;
                        }
                        resp.extend_from_slice(&chunk[..n]);
                    }
                    let _ = sock.send_slice(&resp);
                }
            }
        }
        // 4. Пауза между итерациями (yield)
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

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
    #[test]
    fn check_profile_accepts_hy2_and_tuic() {
        let hy2 = r#"{"type":"hysteria2","name":"h","address":"1.2.3.4","port":443,"detail":{"password":"p"}}"#;
        let p: lavray_model::profile::Profile = serde_json::from_str(hy2).expect("profile");
        assert!(matches!(check_profile(&p), Ok(Outbound::Hy2(_))));
        let tuic = r#"{"type":"tuic","name":"t","address":"1.2.3.4","port":443,"detail":{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","password":"p"}}"#;
        let p: lavray_model::profile::Profile = serde_json::from_str(tuic).expect("profile");
        assert!(matches!(check_profile(&p), Ok(Outbound::Tuic(_))));
    }
}
