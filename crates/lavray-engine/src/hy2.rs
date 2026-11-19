// SPDX-License-Identifier: GPL-3.0-only

//! Hysteria2-клиент (волна QUIC): QUIC через quinn + HTTP/3-минимум для
//! auth (POST /auth, Hysteria-Auth/CC-RX, статус 233), затем TCP-фреймы
//! 0x401 (QUIC varint) с адресом+padding. Паритет Go sing-quic/hysteria2.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::h3_auth::{read_h3_auth_response, send_h3_auth};
use crate::hy2_config::{Hy2Config, Hy2Error, write_varint};
use crate::hy2_stream::Hy2Stream;

pub(crate) const URL_PATH: &str = "/auth";
pub(crate) const AUTH_HEADER: &str = "Hysteria-Auth";
pub(crate) const CC_RX_HEADER: &str = "Hysteria-CC-RX";
pub(crate) const PADDING_HEADER: &str = "Hysteria-Padding";
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

pub(crate) fn varint_len(first_byte: u8) -> usize {
    match first_byte >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

/// Подключение к hysteria2: QUIC + auth (HTTP/3-минимум) → открытый
/// TCP-поток к `host:port`.
///
/// # Errors
/// I/O / TLS / auth (код != 233).
pub async fn connect(cfg: &Hy2Config, host: &str, port: u16) -> Result<Hy2Stream, Hy2Error> {
    if cfg.skip_verify {
        return Err(Hy2Error(
            "skip_verify для QUIC/hysteria2 — подволна 7f-3c-4 (нужен custom verifier с Suite)"
                .into(),
        ));
    }
    let roots = Arc::new({
        let mut r = tokio_rustls::rustls::RootCertStore::empty();
        r.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        r
    });
    let client_cfg = quinn::ClientConfig::with_root_certificates(roots)
        .map_err(|e| Hy2Error(format!("quic tls: {e}")))?;

    let addr = SocketAddr::new(
        cfg.server
            .parse()
            .map_err(|_| Hy2Error("bad server ip (только IP; DNS — 7f-3c-4)".into()))?,
        cfg.server_port,
    );
    let mut endpoint = quinn::Endpoint::client(
        "0.0.0.0:0"
            .parse()
            .map_err(|e| Hy2Error(format!("bind: {e}")))?,
    )
    .map_err(|e| Hy2Error(format!("endpoint: {e}")))?;
    endpoint.set_default_client_config(client_cfg);
    let conn = endpoint
        .connect(addr, &cfg.sni)
        .map_err(|e| Hy2Error(format!("connect: {e}")))?
        .await
        .map_err(|e| Hy2Error(format!("quic handshake: {e}")))?;

    // Auth: HTTP/3 POST /auth с Hysteria-заголовками (status 233 = ok).
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| Hy2Error(format!("open bi: {e}")))?;
    send_h3_auth(&mut send, &cfg.password, cfg.rx_bps)
        .await
        .map_err(Hy2Error)?;
    if !read_h3_auth_response(&mut recv)
        .await
        .map_err(|e| Hy2Error(e.clone()))?
    {
        conn.close(0u32.into(), b"auth failed");
        return Err(Hy2Error("authentication failed (status != 233)".into()));
    }

    // Открыть bi-стрим под TCP-запрос: 0x401 + addr + padding.
    let (mut req_send, mut req_recv) = conn
        .open_bi()
        .await
        .map_err(|e| Hy2Error(format!("open tcp stream: {e}")))?;
    let addr = format!("{host}:{port}");
    let first = write_tcp_request(&addr, &[]);
    req_send
        .write_all(&first)
        .await
        .map_err(|e| Hy2Error(format!("write request: {e}")))?;
    let mut resp = [0u8; 64];
    let n = req_recv
        .read(&mut resp)
        .await
        .map_err(|e| Hy2Error(format!("read response: {e}")))?
        .unwrap_or(0);
    read_tcp_response(&resp[..n]).map_err(|e| Hy2Error(e.0))?;

    Ok(Hy2Stream {
        conn,
        send: req_send,
        recv: req_recv,
    })
}
