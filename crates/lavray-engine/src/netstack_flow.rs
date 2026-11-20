// SPDX-License-Identifier: GPL-3.0-only

//! TcpFlow: принятое TCP-соединение из TUN; listen/accept для netstack.

use std::net::IpAddr;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;

/// Принятое TCP-соединение из TUN для проксирования.
#[derive(Debug, Clone)]
pub struct TcpFlow {
    /// Адрес источника (клиент в TUN-сети).
    pub src: IpAddr,
    /// Адрес назначения (куда шёл трафик).
    pub dst: IpAddr,
    /// Порт назначения.
    pub dst_port: u16,
}

/// Начать слушать TCP-порт в netstack (все входящие — в accept-очередь).
pub(crate) fn listen_port(
    sockets: &mut SocketSet<'static>,
    listeners: &mut Vec<(SocketHandle, u16)>,
    port: u16,
    rx_buf: usize,
    tx_buf: usize,
) {
    let tcp_rx = tcp::SocketBuffer::new(vec![0; rx_buf]);
    let tcp_tx = tcp::SocketBuffer::new(vec![0; tx_buf]);
    let socket = tcp::Socket::new(tcp_rx, tcp_tx);
    let handle = sockets.add(socket);
    sock_listen(sockets, handle, port);
    listeners.push((handle, port));
}

/// Проверить слушающие сокеты: вернуть установленные соединения и
/// пересоздать слушающие сокеты на тех же портах.
pub(crate) fn accept_established(
    sockets: &mut SocketSet<'static>,
    listeners: &mut Vec<(SocketHandle, u16)>,
) -> Vec<(u16, SocketHandle)> {
    let mut out = Vec::new();
    let mut to_add = Vec::new();
    for (handle, port) in listeners.iter() {
        let sock = sockets.get::<tcp::Socket>(*handle);
        if sock.is_active() && sock.may_recv() {
            out.push((*port, *handle));
            let rx_buf = sock.recv_capacity();
            let tx_buf = sock.send_capacity();
            let new_tcp_rx = tcp::SocketBuffer::new(vec![0; rx_buf]);
            let new_tcp_tx = tcp::SocketBuffer::new(vec![0; tx_buf]);
            to_add.push((*port, tcp::Socket::new(new_tcp_rx, new_tcp_tx)));
        }
    }
    for (port, new_socket) in to_add {
        let h = sockets.add(new_socket);
        sock_listen(sockets, h, port);
        listeners.push((h, port));
    }
    out
}

pub(crate) fn sock_listen(sockets: &mut SocketSet<'static>, handle: SocketHandle, port: u16) {
    let sock = sockets.get_mut::<tcp::Socket>(handle);
    let _ = sock.listen(port);
}
