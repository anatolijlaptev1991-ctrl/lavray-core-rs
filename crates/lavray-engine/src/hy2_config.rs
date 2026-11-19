// SPDX-License-Identifier: GPL-3.0-only

//! Конфиг и ошибка hysteria2-клиента.

/// Конфиг hysteria2.
#[derive(Debug, Clone)]
pub struct Hy2Config {
    pub server: String,
    pub server_port: u16,
    pub sni: String,
    pub password: String,
    /// Receive BPS (0 = авто-детект; отправляется в Hysteria-CC-RX).
    pub rx_bps: u64,
    /// Принимать любой сертификат.
    pub skip_verify: bool,
}

/// Ошибка hysteria2.
#[derive(Debug, Clone)]
pub struct Hy2Error(pub String);

impl std::fmt::Display for Hy2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hysteria2: {}", self.0)
    }
}

impl std::error::Error for Hy2Error {}

/// QUIC varint (RFC 9000 §16): 1–8 байт по двум старшим битам.
/// Касты в тегах — осознанные (значения уже замаскированы & 0x3F).
#[allow(clippy::cast_possible_truncation)]
pub fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0x40 {
        out.push(v as u8);
    } else if v < 0x4000 {
        let b = (v as u16).to_be_bytes();
        out.extend_from_slice(&[0x40 | (b[0] & 0x3F), b[1]]);
    } else if v < 0x4000_0000 {
        let b = (v as u32).to_be_bytes();
        out.extend_from_slice(&[0x80 | (b[0] & 0x3F), b[1], b[2], b[3]]);
    } else {
        let b = v.to_be_bytes();
        out.extend_from_slice(&[
            0xC0 | (b[0] & 0x3F),
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
        ]);
    }
}
