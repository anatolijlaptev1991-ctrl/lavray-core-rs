// SPDX-License-Identifier: GPL-3.0-only

//! TUIC v5-клиент (волна QUIC, паритет sing-quic/tuic):
//! QUIC (quinn) + TLS → uni-stream auth [ver=5, cmd=1, uuid16, token32]
//! (token = ExportKeyingMaterial(uuid, password, 32)) → bi-stream
//! TCP-запрос [ver=5, cmd=2, ATYP-addr] + payload.

use crate::addr::TargetAddr;

/// TUIC protocol version.
pub const VERSION: u8 = 5;
/// Command: authenticate (uni stream). sing-quic: отдельный const-блок,
/// iota с 0.
pub const CMD_AUTHENTICATE: u8 = 0;
/// Command: TCP connect (bi stream) — вторая константа блока.
pub const CMD_CONNECT: u8 = 1;
/// Command: UDP packet (datagram).
pub const CMD_PACKET: u8 = 2;

/// Конфиг tuic.
#[derive(Debug, Clone)]
pub struct TuicConfig {
    pub server: String,
    pub server_port: u16,
    pub sni: String,
    pub uuid: String,
    pub password: String,
    /// Принимать любой сертификат.
    pub skip_verify: bool,
}

/// Ошибка tuic.
#[derive(Debug, Clone)]
pub struct TuicError(pub String);

impl std::fmt::Display for TuicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tuic: {}", self.0)
    }
}

impl std::error::Error for TuicError {}

/// Парсинг UUID в 16 байт (hyphenated или hex).
///
/// # Errors
/// Неверный формат.
pub fn parse_uuid(s: &str) -> Result<[u8; 16], TuicError> {
    let clean: String = s.chars().filter(|c| *c != '-').collect();
    if clean.len() != 32 {
        return Err(TuicError(format!("bad uuid length {}", clean.len())));
    }
    let mut out = [0u8; 16];
    for (i, chunk) in clean.as_bytes().chunks(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, TuicError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(TuicError(format!("bad uuid hex digit {}", b as char))),
    }
}

/// ATYP-адрес (sing metadata Serializer, tuic: portFirst=false → адрес
/// ПЕРЕД портом): 00 fqdn(len+host), 01 ipv4, 02 ipv6; порт u16 BE в конце.
pub fn write_addr_port(out: &mut Vec<u8>, target: &TargetAddr) {
    match target {
        TargetAddr::Domain(d, port) => {
            out.push(0x00);
            out.push(u8::try_from(d.len()).unwrap_or(255));
            out.extend_from_slice(d.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V4(v), port) => {
            out.push(0x01);
            out.extend_from_slice(&v.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(v), port) => {
            out.push(0x02);
            out.extend_from_slice(&v.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

/// Экспорт keying material TUIC: HKDF-Expand с RFC 5705-семантикой
/// (label = uuid-строка, context = password). quinn предоставляет
/// export_keying_material через rustls connection — здесь формула из Go:
/// tls.ExportKeyingMaterial(uuid, password, 32) = HMAC-цепочка.
/// На практике TUIC-сервер сверяет токен, вычисленный ТОЧНО как в Go TLS;
/// для паритета реализуем через rustls export_keying_material при наличии
/// соединения — здесь заготовка принимает готовый токен.
#[must_use]
pub fn auth_request(uuid: &[u8; 16], token: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 16 + 32);
    out.push(VERSION);
    out.push(CMD_AUTHENTICATE);
    out.extend_from_slice(uuid);
    out.extend_from_slice(token);
    out
}

/// TCP-запрос: [ver=5][cmd=2][addr] + первый payload-чанк.
#[must_use]
pub fn connect_request(target: &TargetAddr, first_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 1 + 16 + 255 + first_payload.len());
    out.push(VERSION);
    out.push(CMD_CONNECT);
    write_addr_port(&mut out, target);
    out.extend_from_slice(first_payload);
    out
}

pub use crate::tuic_conn::{TuicStream, connect};
