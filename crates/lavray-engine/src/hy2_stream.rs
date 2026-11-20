// SPDX-License-Identifier: GPL-3.0-only

//! Hy2Stream: приложение-канал hysteria2 (TCP через QUIC stream).

use crate::relay::{UpRead, UpWrite};
use quinn::Connection;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// Поток hysteria2 TCP (data через QUIC stream после запроса).
pub struct Hy2Stream {
    pub(crate) conn: Connection,
    /// H3 control-поток (SETTINGS) — держится открытым всё соединение
    /// (чтения нет: нужен только живой дескриптор).
    #[allow(dead_code)]
    pub(crate) control: quinn::SendStream,
    /// QPACK encoder/decoder потоки — держатся открытыми (RFC 9204 §4.2).
    #[allow(dead_code)]
    pub(crate) qpack_enc: quinn::SendStream,
    #[allow(dead_code)]
    pub(crate) qpack_dec: quinn::SendStream,
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
}

impl Hy2Stream {
    /// Подключение QUIC (для close_with_error).
    #[must_use]
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Разделить на половины (UpRead/UpWrite). H3 uni-потоки (control +
    /// QPACK) живут в hold-дуге обеих половин — их дроп дал бы RESET и
    /// сервер разорвал бы соединение; соединение закрывается, когда
    /// умирают обе половины.
    #[must_use]
    pub fn split(self) -> (UpRead, UpWrite) {
        let hold = Arc::new([self.control, self.qpack_enc, self.qpack_dec]);
        (
            Box::pin(QuicReadHalf {
                recv: self.recv,
                _hold: Arc::clone(&hold),
            }),
            Box::pin(QuicWriteHalf {
                send: self.send,
                _hold: hold,
            }),
        )
    }
}

/// Половина чтения (recv + hold uni-потоков).
struct QuicReadHalf {
    recv: quinn::RecvStream,
    _hold: Arc<[quinn::SendStream; 3]>,
}

/// Половина записи (send + hold uni-потоков).
struct QuicWriteHalf {
    send: quinn::SendStream,
    _hold: Arc<[quinn::SendStream; 3]>,
}

impl AsyncRead for QuicReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        dst: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, dst)
    }
}

impl AsyncWrite for QuicWriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

impl AsyncWrite for Hy2Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

impl AsyncRead for Hy2Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        dst: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, dst)
    }
}
