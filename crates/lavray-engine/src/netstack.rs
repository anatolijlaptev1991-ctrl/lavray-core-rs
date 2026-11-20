// SPDX-License-Identifier: GPL-3.0-only

//! User-space TCP/IP netstack (волна 7f-3c-4b): TUN-девайс ↔ smoltcp
//! socketset. Принимает TCP-соединения из TUN и отдаёт их в
//! proxy-pipeline движка (mixed-style server поверх TUN).
//!
//! Ограничение: однопоточный event-loop с каналами — blазинг через
//! отсутствие системных вызовов на каждый пакет.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

/// Ошибка netstack.
#[derive(Debug)]
pub struct NetstackError(pub String);

impl std::fmt::Display for NetstackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "netstack: {}", self.0)
    }
}

impl std::error::Error for NetstackError {}

/// Входящий TCP-флоу из TUN: (peer, порт назначения, приёмник данных).
pub struct AcceptedTcp {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub socket: tcp::Socket<'static>,
}

/// TUN-девайс для netstack: байтовый канал (замена wintun Read/Write).
pub trait TunIo: Send {
    /// Прочитать исходящий пакет (IP-фрейм) из TUN.
    ///
    /// # Errors
    /// I/O.
    fn read_packet(&mut self) -> Result<Vec<u8>, std::io::Error>;
    /// Записать входящий пакет в TUN.
    ///
    /// # Errors
    /// I/O.
    fn write_packet(&mut self, pkt: &[u8]) -> Result<(), std::io::Error>;
}

/// Внутренний smoltcp-Device поверх TunIo (swap-канал).
struct TunDeviceAdapter {
    rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl Device for TunDeviceAdapter {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx_queue.lock().ok()?.pop_front()?;
        Some((
            RxToken { buffer: pkt },
            TxToken {
                queue: Arc::clone(&self.tx_queue),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            queue: Arc::clone(&self.tx_queue),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps.max_burst_size = None;
        caps
    }
}

struct RxToken {
    buffer: Vec<u8>,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut { self.buffer })
    }
}

struct TxToken {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut pkt = vec![0u8; len];
        let result = f(&mut pkt);
        if let Ok(mut q) = self.queue.lock() {
            q.push_back(pkt);
        }
        result
    }
}

/// Netstack-адресация: наш адрес в TUN-сети.
#[derive(Debug, Clone)]
pub struct NetstackConfig {
    /// Адрес TUN-интерфейса (например 172.19.0.1).
    pub address: IpAddr,
    /// Префикс (например 24).
    pub prefix: u8,
    /// MTU (1500 — стандарт).
    pub mtu: u16,
}

/// User-space netstack: держит smoltcp-состояние и собирает входящие
/// TCP-соединения в очередь для движка. Поля читаются в poll-loop 7f-3c-4b
/// (wintun/wire интеграция); сейчас каркас.
#[allow(dead_code)]
pub struct Netstack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device_adapter: TunDeviceAdapter,
    cfg: NetstackConfig,
    /// Принятые TCP-соединения (данные через smoltcp-сокеты).
    accepted: VecDeque<AcceptedTcp>,
}

impl Netstack {
    /// Создать netstack поверх TunIo.
    ///
    /// # Errors
    /// Некорректный адрес.
    pub fn new(cfg: NetstackConfig, _tun: Box<dyn TunIo>) -> Result<Self, NetstackError> {
        let iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        let adapter = TunDeviceAdapter {
            rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            tx_queue: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut iface = Interface::new(iface_cfg, &mut placeholder_of(&adapter), Instant::now());
        let addr = match cfg.address {
            IpAddr::V4(v) => IpAddress::Ipv4(Ipv4Address::from_bytes(&v.octets())),
            IpAddr::V6(v) => IpAddress::Ipv6(v.into()),
        };
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(addr, cfg.prefix));
        });
        // listen-порт только через tcp sockets — движок добавляет их сам
        Ok(Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device_adapter: adapter,
            cfg,
            accepted: VecDeque::new(),
        })
    }
}

/// Ложный девайс для первичной инициализации Interface (без пакетов).
fn placeholder_of(a: &TunDeviceAdapter) -> TunDeviceAdapter {
    TunDeviceAdapter {
        rx_queue: Arc::clone(&a.rx_queue),
        tx_queue: Arc::clone(&a.tx_queue),
    }
}
