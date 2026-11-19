// SPDX-License-Identifier: GPL-3.0-only

//! TUN-слой волна 7f-3c-3: парсинг IP-пакетов из TUN-устройства
//! (IPv4/IPv6 заголовки, TCP/UDP демукс) — переносимое ядро без
//! привязки к wintun/udev. Привязка к девайсу — 7f-3c-4.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Распарсенный IP-пакет из TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacket {
    /// Адрес источника.
    pub src: IpAddr,
    /// Адрес назначения.
    pub dst: IpAddr,
    /// Протокол верхнего уровня (6 = TCP, 17 = UDP).
    pub protocol: u8,
    /// Полезная нагрузка L4 (TCP/UDP заголовок + данные).
    pub l4_payload: Vec<u8>,
}

/// Ошибка разбора пакета.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketError(pub String);

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tun packet: {}", self.0)
    }
}

impl std::error::Error for PacketError {}

/// Разобрать IP-пакет (IPv4 или IPv6).
///
/// # Errors
/// Труncated header / не-IP версия.
pub fn parse_ip(raw: &[u8]) -> Result<IpPacket, PacketError> {
    if raw.is_empty() {
        return Err(PacketError("empty packet".into()));
    }
    let version = raw[0] >> 4;
    match version {
        4 => parse_ipv4(raw),
        6 => parse_ipv6(raw),
        v => Err(PacketError(format!("unsupported ip version {v}"))),
    }
}

fn parse_ipv4(raw: &[u8]) -> Result<IpPacket, PacketError> {
    if raw.len() < 20 {
        return Err(PacketError("ipv4 header truncated".into()));
    }
    let ihl = usize::from(raw[0] & 0x0F) * 4;
    if ihl < 20 {
        return Err(PacketError(format!("bad ihl {ihl}")));
    }
    if raw.len() < ihl {
        return Err(PacketError("ipv4 options truncated".into()));
    }
    let protocol = raw[9];
    let src = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);
    let dst = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]);
    let total = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
    let l4_end = total.min(raw.len());
    if l4_end < ihl {
        return Err(PacketError("ipv4 total length < header".into()));
    }
    Ok(IpPacket {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        protocol,
        l4_payload: raw[ihl..l4_end].to_vec(),
    })
}

fn parse_ipv6(raw: &[u8]) -> Result<IpPacket, PacketError> {
    if raw.len() < 40 {
        return Err(PacketError("ipv6 header truncated".into()));
    }
    let protocol = raw[6]; // next header
    let src = IpAddr::V6(Ipv6Addr::new(
        u16::from_be_bytes([raw[8], raw[9]]),
        u16::from_be_bytes([raw[10], raw[11]]),
        u16::from_be_bytes([raw[12], raw[13]]),
        u16::from_be_bytes([raw[14], raw[15]]),
        u16::from_be_bytes([raw[16], raw[17]]),
        u16::from_be_bytes([raw[18], raw[19]]),
        u16::from_be_bytes([raw[20], raw[21]]),
        u16::from_be_bytes([raw[22], raw[23]]),
    ));
    let dst = IpAddr::V6(Ipv6Addr::new(
        u16::from_be_bytes([raw[24], raw[25]]),
        u16::from_be_bytes([raw[26], raw[27]]),
        u16::from_be_bytes([raw[28], raw[29]]),
        u16::from_be_bytes([raw[30], raw[31]]),
        u16::from_be_bytes([raw[32], raw[33]]),
        u16::from_be_bytes([raw[34], raw[35]]),
        u16::from_be_bytes([raw[36], raw[37]]),
        u16::from_be_bytes([raw[38], raw[39]]),
    ));
    let payload_len = usize::from(u16::from_be_bytes([raw[4], raw[5]]));
    let l4_end = (40 + payload_len).min(raw.len());
    Ok(IpPacket {
        src,
        dst,
        protocol,
        l4_payload: raw[40..l4_end].to_vec(),
    })
}

/// Распарсенный L4-флоу из пакета.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4Flow {
    /// TCP: (src_port, dst_port, seq, ack, флаги, payload).
    Tcp {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: Vec<u8>,
    },
    /// UDP: (src_port, dst_port, payload).
    Udp {
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    },
    /// Прочий протокол L4 — пропускается.
    Other(u8),
}

/// Демукс L4 из пакета.
///
/// # Errors
/// TCP/UDP заголовок truncated.
pub fn demux(packet: &IpPacket) -> Result<L4Flow, PacketError> {
    match packet.protocol {
        6 => {
            let p = &packet.l4_payload;
            if p.len() < 20 {
                return Err(PacketError("tcp header truncated".into()));
            }
            Ok(L4Flow::Tcp {
                src_port: u16::from_be_bytes([p[0], p[1]]),
                dst_port: u16::from_be_bytes([p[2], p[3]]),
                seq: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
                ack: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
                flags: p[13],
                payload: p[20..].to_vec(),
            })
        }
        17 => {
            let p = &packet.l4_payload;
            if p.len() < 8 {
                return Err(PacketError("udp header truncated".into()));
            }
            Ok(L4Flow::Udp {
                src_port: u16::from_be_bytes([p[0], p[1]]),
                dst_port: u16::from_be_bytes([p[2], p[3]]),
                payload: p[8..].to_vec(),
            })
        }
        other => Ok(L4Flow::Other(other)),
    }
}

/// TCP-флаги (биты поля flags).
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
