// SPDX-License-Identifier: GPL-3.0-only

//! TUIC v5-соединение: QUIC handshake, auth uni-stream, TCP bi-stream.

use crate::addr::TargetAddr;
use crate::relay::{UpRead, UpWrite};
use crate::tuic::{TuicConfig, TuicError, auth_request, connect_request, parse_uuid};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// Подключение к tuic-серверу и открытие TCP-туннеля до цели.
///
/// # Errors
/// I/O / TLS / QUIC / uuid.
pub async fn connect(
    cfg: &TuicConfig,
    target: &TargetAddr,
    server_addr: SocketAddr,
) -> Result<TuicStream, TuicError> {
    let uuid = parse_uuid(&cfg.uuid)?;

    // TLS 1.3: webpki-roots или skip_verify (dangerous-верификатор).
    let client_cfg = crate::quic_tls::client_config(cfg.skip_verify, &["h3"])
        .map_err(|e| TuicError(e.clone()))?;
    let mut endpoint = quinn::Endpoint::client(
        "0.0.0.0:0"
            .parse()
            .map_err(|e| TuicError(format!("bind: {e}")))?,
    )
    .map_err(|e| TuicError(format!("endpoint: {e}")))?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint
        .connect(server_addr, &cfg.sni)
        .map_err(|e| TuicError(format!("connect: {e}")))?
        .await
        .map_err(|e| TuicError(format!("quic handshake: {e}")))?;

    // 1. Auth uni-stream: [5][1][uuid16][token32].
    let token = export_keying(&conn, &uuid, cfg.password.as_bytes())?;
    let mut auth_send = conn
        .open_uni()
        .await
        .map_err(|e| TuicError(format!("open uni: {e}")))?;
    auth_send
        .write_all(&auth_request(&uuid, &token))
        .await
        .map_err(|e| TuicError(format!("write auth: {e}")))?;
    auth_send
        .finish()
        .map_err(|e| TuicError(format!("finish auth: {e}")))?;

    // 2. TCP bi-stream: [5][2][addr] + payload.
    let (mut req_send, req_recv) = conn
        .open_bi()
        .await
        .map_err(|e| TuicError(format!("open bi: {e}")))?;
    let first = connect_request(target, &[]);
    req_send
        .write_all(&first)
        .await
        .map_err(|e| TuicError(format!("write connect: {e}")))?;

    Ok(TuicStream {
        conn,
        send: req_send,
        recv: req_recv,
    })
}

/// ExportKeyingMaterial из TLS 1.3 (RFC 5705/8446 §7.5): exporter с
/// label = uuid-строка, context = password. quinn выставляет через
/// quinn::Connection::export_keying_material? — нет: доступ через
/// rustls. Здесь реализация той же HMAC-цепочки, что в Go crypto/tls:
///   secret = HKDF-Expand-Label(master, "exporter", hash(""), 48)
///   key_material = HMAC(secret, label || 0 || context || len16)
/// TUIC использует label = uuid (строка) и context = password.
pub(crate) fn export_keying(
    conn: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> Result<[u8; 32], TuicError> {
    // Label — СЫРЫЕ 16 байт UUID (parity Go string(uuid[:])); наивный
    // String::from_utf8_lossy заменяет невалидные байты на U+FFFD и
    // ломает токен (сервер: token mismatch).
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, uuid, password)
        .map_err(|e| TuicError(format!("export keying: {e:?}")))?;
    Ok(out)
}

/// Поток TUIC TCP.
pub struct TuicStream {
    #[allow(dead_code)] // используется для close_with_error в 7f-3c-4b
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl TuicStream {
    /// Разделить на половины (UpRead/UpWrite): quinn-стримы держат
    /// Arc соединения — QUIC-соединение закрывается, когда умирают
    /// обе половины.
    #[must_use]
    pub fn split(self) -> (UpRead, UpWrite) {
        (Box::pin(self.recv), Box::pin(self.send))
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, dst)
    }
}
