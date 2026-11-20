// SPDX-License-Identifier: GPL-3.0-only

//! Типы netstack: ошибка, входящий TCP-флоу, trait TunIo.

use smoltcp::socket::tcp;
use std::net::IpAddr;

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
