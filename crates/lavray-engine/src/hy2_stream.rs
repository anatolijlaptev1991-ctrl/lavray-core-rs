// SPDX-License-Identifier: GPL-3.0-only

//! Hy2Stream: приложение-канал hysteria2 (TCP через QUIC stream).

use quinn::Connection;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// Поток hysteria2 TCP (data через QUIC stream после запроса).
pub struct Hy2Stream {
    pub(crate) conn: Connection,
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
}

impl Hy2Stream {
    /// Подключение QUIC (для close_with_error).
    #[must_use]
    pub fn conn(&self) -> &Connection {
        &self.conn
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
