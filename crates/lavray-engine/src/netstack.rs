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

use crate::netstack_flow::TcpFlow;
use crate::netstack_phy::{RxToken, TxToken};
use crate::netstack_types::{AcceptedTcp, NetstackError, TunIo};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

/// TUN-девайс для netstack: байтовый канал (замена wintun Read/Write).
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
            crate::netstack_phy::rx_token(pkt),
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
    tun: Box<dyn TunIo>,
    iface: Interface,
    sockets: SocketSet<'static>,
    device_adapter: TunDeviceAdapter,
    cfg: NetstackConfig,
    /// Принятые TCP-соединения (данные через smoltcp-сокеты).
    accepted: VecDeque<AcceptedTcp>,
    /// Слушающие сокеты: (handle, порт).
    listeners: Vec<(smoltcp::iface::SocketHandle, u16)>,
}

impl Netstack {
    /// Создать netstack поверх TunIo.
    ///
    /// # Errors
    /// Некорректный адрес.
    pub fn new(cfg: NetstackConfig, tun: Box<dyn TunIo>) -> Result<Self, NetstackError> {
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
            tun,
            iface,
            sockets: SocketSet::new(Vec::new()),
            device_adapter: adapter,
            cfg,
            accepted: VecDeque::new(),
            listeners: Vec::new(),
        })
    }

    /// Один шаг poll: обработать пакеты из TunIo и smoltcp-сокеты.
    /// Возвращает TCP-флоу, готовые к проксированию.
    /// Начать слушать TCP-порт (делегат netstack_flow).
    pub fn listen_port(&mut self, port: u16, rx_buf: usize, tx_buf: usize) {
        crate::netstack_flow::listen_port(
            &mut self.sockets,
            &mut self.listeners,
            port,
            rx_buf,
            tx_buf,
        );
    }

    /// Установленные соединения на слушающих портах.
    pub fn accept_established(&mut self) -> Vec<(u16, smoltcp::iface::SocketHandle)> {
        crate::netstack_flow::accept_established(&mut self.sockets, &mut self.listeners)
    }

    /// Изменяемый доступ к сокету по handle (для relay).
    pub fn socket_mut(
        &mut self,
        handle: smoltcp::iface::SocketHandle,
    ) -> &mut smoltcp::socket::tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(handle)
    }

    pub fn poll(&mut self) -> Result<Vec<TcpFlow>, NetstackError> {
        let flows = Vec::new();
        // 1. Пакеты из TUN → rx-очередь netstack
        while let Ok(pkt) = self.tun.read_packet() {
            if let Ok(mut q) = self.device_adapter.rx_queue.lock() {
                q.push_back(pkt);
            }
        }
        // 2. smoltcp poll: обработка rx/tx
        let now = Instant::now();
        self.iface
            .poll(now, &mut self.device_adapter, &mut self.sockets);
        // 3. tx-очередь → TUN
        while let Some(pkt) = self
            .device_adapter
            .tx_queue
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front())
        {
            self.tun
                .write_packet(&pkt)
                .map_err(|e| NetstackError(format!("tun write: {e}")))?;
        }
        // 4. Разбор новых TCP-соединений (SYN/ESTABLISHED через smoltcp listening sockets — 7f-3c-4c)
        Ok(flows)
    }
}

/// Ложный девайс для первичной инициализации Interface (без пакетов).
fn placeholder_of(a: &TunDeviceAdapter) -> TunDeviceAdapter {
    TunDeviceAdapter {
        rx_queue: Arc::clone(&a.rx_queue),
        tx_queue: Arc::clone(&a.tx_queue),
    }
}
