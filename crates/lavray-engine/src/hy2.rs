// SPDX-License-Identifier: GPL-3.0-only

//! Hysteria2 wire-формат (волна QUIC): QUIC varint, TCP-фреймы 0x401
//! (адрес + padding), TCP-ответ. Клиентский коннект — в `hy2_conn`.
//! Паритет Go sing-quic/hysteria2 internal/protocol.

use crate::hy2_config::{Hy2Error, write_varint};

pub use crate::hy2_config::Hy2Config;

pub(crate) const URL_PATH: &str = "/auth";
const FRAME_TCP_REQUEST: u64 = 0x401;
/// Padding-строка Go (authRequestPadding.String()).
pub(crate) const AUTH_PADDING: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

/// QUIC varint: прочитать и вернуть (значение, число байт).
///
/// # Errors
/// EOF/переполнение.
pub fn read_varint(data: &[u8]) -> Result<(u64, usize), Hy2Error> {
    if data.is_empty() {
        return Err(Hy2Error("varint: eof".into()));
    }
    let first = data[0];
    let (len, prefix_mask) = match first >> 6 {
        0 => (1, 0x3F),
        1 => (2, 0x3F),
        2 => (4, 0x3F),
        _ => (8, 0x3F),
    };
    if data.len() < len {
        return Err(Hy2Error("varint: truncated".into()));
    }
    let mut v = u64::from(first & prefix_mask);
    for byte in &data[1..len] {
        v = (v << 8) | u64::from(*byte);
    }
    Ok((v, len))
}

/// TCP-запрос hysteria2: 0x401 + varint(addr_len) + addr + varint(pad_len) + pad.
#[must_use]
pub fn write_tcp_request(addr: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(addr.len() + payload.len() + 32);
    write_varint(&mut out, FRAME_TCP_REQUEST);
    write_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    write_varint(&mut out, AUTH_PADDING.len() as u64);
    out.extend_from_slice(AUTH_PADDING.as_bytes());
    out.extend_from_slice(payload);
    out
}

/// TCP-ответ: status(1) + varint(msg_len) + msg + varint(pad_len) + pad.
///
/// # Errors
/// EOF/битая длина/статус != 0.
pub fn read_tcp_response(data: &[u8]) -> Result<(), Hy2Error> {
    if data.is_empty() {
        return Err(Hy2Error("tcp response: eof".into()));
    }
    if data[0] != 0 {
        let (msg_len, _) = read_varint(&data[1..])?;
        let msg_start = 1 + varint_len(data[1]);
        let end = (msg_start + usize::try_from(msg_len).unwrap_or(data.len())).min(data.len());
        let msg = String::from_utf8_lossy(&data[msg_start..end]);
        return Err(Hy2Error(format!("remote error: {msg}")));
    }
    Ok(())
}

/// QUIC varint из потока (байт за байтом, без перечитывания данных).
///
/// # Errors
/// I/O.
pub(crate) async fn read_varint_stream(
    recv: &mut quinn::RecvStream,
) -> Result<(u64, usize), Hy2Error> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|e| Hy2Error(format!("read varint: {e}")))?;
    let len = varint_len(first[0]);
    let mut buf = vec![first[0]];
    buf.resize(len, 0);
    if len > 1 {
        recv.read_exact(&mut buf[1..])
            .await
            .map_err(|e| Hy2Error(format!("read varint: {e}")))?;
    }
    read_varint(&buf).map_err(|e| Hy2Error(e.0))
}

pub(crate) fn varint_len(first_byte: u8) -> usize {
    match first_byte >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}
