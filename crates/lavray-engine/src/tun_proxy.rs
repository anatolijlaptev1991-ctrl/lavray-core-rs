use crate::direct::Outbound;
use crate::netstack::{Netstack, NetstackConfig};
use crate::netstack_types::NetstackError;
use crate::profile_outbound::{ProfileOutbound, from_profile};
use crate::tun_relay::{FlowState, ToClient, spawn_upstream};
use std::collections::HashMap;
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
        Ok(ProfileOutbound::Vless(v)) => Ok(Outbound::Vless(Box::new(v))),
        Ok(ProfileOutbound::Hysteria2(h)) => Ok(Outbound::Hy2(h)),
        Ok(ProfileOutbound::Tuic(t)) => Ok(Outbound::Tuic(t)),
        Ok(other) => Err(ProxyError(format!(
            "протокол ещё не подключён к tun_proxy poll-циклу: {other:?}"
        ))),
        Err(e) => Err(ProxyError(e.to_string())),
    }
}

/// Активное соединение poll-цикла.
struct Flow {
    state: FlowState,
    /// Sender жив? (None = закрыт: клиент закрылся, задача завершится)
    sender_alive: bool,
}

/// Запустить poll-цикл: TUN + netstack + канальный relay. Полный
/// двунаправленный поток: данные клиента → upstream-задаче, ответы —
/// обратно через каналы; цикл никогда не ждёт EOF.
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
    let outbound = Arc::new(cfg.outbound);
    let mut flows: HashMap<smoltcp::iface::SocketHandle, Flow> = HashMap::new();
    let mut buf = [0u8; 4096];
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        if let Err(e) = netstack.poll() {
            return Err(ProxyError(e.0));
        }
        // 1. Новые установленные соединения → upstream-задачи
        for (target, handle) in netstack.accept_targets() {
            let state = spawn_upstream(Arc::clone(&outbound), target);
            flows.insert(
                handle,
                Flow {
                    state,
                    sender_alive: true,
                },
            );
        }
        // 2. Данные клиента → upstream-задачам; закрытие клиентов
        let mut to_remove = Vec::new();
        for (handle, flow) in &mut flows {
            let sock = netstack.socket_mut(*handle);
            let client_fin = !sock.can_recv();
            let dead = !sock.is_active();
            if !flow.sender_alive && (client_fin || dead) {
                flow.sender_alive = false;
            }
            if flow.sender_alive && sock.can_recv() {
                match sock.recv_slice(&mut buf) {
                    Ok(0) | Err(_) => flow.sender_alive = false,
                    Ok(n) => {
                        let _ = flow.state.to_up.send(buf[..n].to_vec());
                    }
                }
            }
            if flow.sender_alive && (dead || client_fin) {
                flow.sender_alive = false;
            }
            if !flow.sender_alive {
                to_remove.push(*handle);
            }
        }
        for h in to_remove {
            flows.remove(&h);
        }
        // 3. Ответы upstream → клиентам
        let mut drain = Vec::new();
        for (handle, flow) in &mut flows {
            let sock = netstack.socket_mut(*handle);
            let mut tmp: Vec<Vec<u8>> = Vec::new();
            let mut dead = false;
            while let Ok(msg) = flow.state.from_up.try_recv() {
                match msg {
                    ToClient::Data(d) => tmp.push(d),
                    ToClient::Eof => {
                        sock.close();
                        dead = true;
                    }
                }
            }
            if dead {
                drain.push(*handle);
                continue;
            }
            for d in tmp {
                let mut off = 0;
                while off < d.len() {
                    match sock.send_slice(&d[off..]) {
                        Ok(n) if n > 0 => off += n,
                        Ok(_) => break, // send-буфер полон — дотомкнем позже
                        Err(_) => {
                            flow.sender_alive = false;
                            break;
                        }
                    }
                }
                if !flow.sender_alive {
                    break;
                }
            }
        }
        for h in drain {
            if let Some(f) = flows.get_mut(&h) {
                f.sender_alive = false;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Обёртка NetstackError для ProxyError (строка внутри).
impl From<NetstackError> for ProxyError {
    fn from(e: NetstackError) -> Self {
        Self(e.0)
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
