// SPDX-License-Identifier: GPL-3.0-only

//! Sniffed — поток с «подсмотренном» первым байтом: детект протокола mixed
//! (0x05 = SOCKS5, иначе HTTP) съедает байт до парсеров; обёртка отдаёт его
//! первым, не искажая порядок. Zero-cost: одна ветка на первый poll_read.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Поток с непрочитанным первым байтом.
pub struct Sniffed<S> {
    inner: S,
    first: Option<u8>,
}

impl<S> Sniffed<S> {
    /// Обернуть, возвращая байт `first` перед данными `inner`.
    pub fn new(inner: S, first: u8) -> Self {
        Self {
            inner,
            first: Some(first),
        }
    }

    /// Забрать внутренний поток (сброс нечитанного байта недопустим: поле
    /// обязано быть None — отдаётся только после исчерпания).
    pub fn into_inner(self) -> S {
        debug_assert!(
            self.first.is_none(),
            "первый байт не отдан парсеру — порядок байт бы исказился"
        );
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Sniffed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(b) = self.first.take() {
            buf.put_slice(&[b]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Sniffed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
