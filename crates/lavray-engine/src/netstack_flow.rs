// SPDX-License-Identifier: GPL-3.0-only

//! TcpFlow: принятое TCP-соединение из TUN; listen/accept для netstack.
//! Модель gvisor (sing-box TUN): слушающий сокет создаётся ПОД КОНКРЕТНЫЙ
//! dst из SYN — цель (dst:port) читается из local_endpoint сокета; чужой
//! dst не обязан быть адресом интерфейса (smoltcp accepts() матчит по
//! listen_endpoint).

use std::net::{IpAddr, Ipv4Addr};

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;

/// Адрес слушателя: конкретный (перехват SYN на этот dst) или wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ListenAddr(pub IpAddr, pub u16);

impl ListenAddr {
    fn endpoint(self) -> IpEndpoint {
        IpEndpoint::new(to_smoltcp_ip(self.0), self.1)
    }
}

fn to_smoltcp_ip(ip: IpAddr) -> smoltcp::wire::IpAddress {
    match ip {
        IpAddr::V4(v) => v.into(),
        IpAddr::V6(v) => v.into(),
    }
}

/// SYN-перехват: убедиться, что есть свободный слушатель на dst:port
/// (на каждый SYN — по одному свободному; свободный = state Listen).
pub(crate) fn catch_syn(
    sockets: &mut SocketSet<'static>,
    listeners: &mut Vec<(SocketHandle, ListenAddr)>,
    dst: IpAddr,
    port: u16,
) {
    let want = ListenAddr(dst, port);
    let have_free = listeners
        .iter()
        .any(|(h, la)| *la == want && sockets.get::<tcp::Socket>(*h).state() == tcp::State::Listen);
    if have_free {
        return;
    }
    add_listener(sockets, listeners, want);
}

/// Слушать конкретный порт на wildcard-адресе (0.0.0.0) — спец-режим.
pub(crate) fn listen_port(
    sockets: &mut SocketSet<'static>,
    listeners: &mut Vec<(SocketHandle, ListenAddr)>,
    port: u16,
    rx_buf: usize,
    tx_buf: usize,
) {
    let want = ListenAddr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    add_listener_buf(sockets, listeners, want, rx_buf, tx_buf);
}

fn add_listener(
    sockets: &mut SocketSet<'static>,
    listeners: &mut Vec<(SocketHandle, ListenAddr)>,
    addr: ListenAddr,
) {
    add_listener_buf(sockets, listeners, addr, 65535, 65535);
}

fn add_listener_buf(
    sockets: &mut SocketSet<'static>,
    listeners: &mut Vec<(SocketHandle, ListenAddr)>,
    addr: ListenAddr,
    rx_buf: usize,
    tx_buf: usize,
) {
    let tcp_rx = tcp::SocketBuffer::new(vec![0; rx_buf]);
    let tcp_tx = tcp::SocketBuffer::new(vec![0; tx_buf]);
    let socket = tcp::Socket::new(tcp_rx, tcp_tx);
    let handle = sockets.add(socket);
    sock_listen(sockets, handle, addr.endpoint());
    listeners.push((handle, addr));
}

/// Проверить слушающие сокеты: вернуть установленные соединения
/// (цель = local_endpoint слушателя) и пересоздать слушатели.
pub(crate) fn accept_established(
    sockets: &mut SocketSet<'static>,
    listeners: &mut Vec<(SocketHandle, ListenAddr)>,
) -> Vec<(IpAddr, u16, SocketHandle)> {
    let mut out = Vec::new();
    let mut to_add = Vec::new();
    for (handle, la) in listeners.iter() {
        let sock = sockets.get::<tcp::Socket>(*handle);
        if sock.is_active() && sock.may_recv() {
            out.push((la.0, la.1, *handle));
            let rx_buf = sock.recv_capacity();
            let tx_buf = sock.send_capacity();
            let new_tcp_rx = tcp::SocketBuffer::new(vec![0; rx_buf]);
            let new_tcp_tx = tcp::SocketBuffer::new(vec![0; tx_buf]);
            to_add.push((*la, tcp::Socket::new(new_tcp_rx, new_tcp_tx)));
        }
    }
    for (la, new_socket) in to_add {
        let h = sockets.add(new_socket);
        sock_listen(sockets, h, la.endpoint());
        listeners.push((h, la));
    }
    out
}

pub(crate) fn sock_listen(sockets: &mut SocketSet<'static>, handle: SocketHandle, ep: IpEndpoint) {
    let sock = sockets.get_mut::<tcp::Socket>(handle);
    let _ = sock.listen(ep);
}

/// SYN-перехват из сырого пакета: TCP SYN (без ACK) → свободный слушатель
/// на dst:port (gvisor-модель; чужой dst не обязан быть адресом iface).
pub(crate) fn catch_syn_packet(
    sockets: &mut SocketSet<'static>,
    listeners: &mut Vec<(SocketHandle, ListenAddr)>,
    pkt: &[u8],
) {
    use crate::tun::{TCP_ACK, TCP_SYN, demux, parse_ip};
    let Ok(ip) = parse_ip(pkt) else {
        return;
    };
    if ip.protocol != 6 {
        return;
    }
    let Ok(l4) = demux(&ip) else {
        return;
    };
    if let crate::tun::L4Flow::Tcp {
        dst_port, flags, ..
    } = l4
        && flags & TCP_SYN == TCP_SYN
        && flags & TCP_ACK == 0
    {
        catch_syn(sockets, listeners, ip.dst, dst_port);
    }
}
