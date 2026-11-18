// SPDX-License-Identifier: GPL-3.0-only

//! Пишущая половина SS-туннеля (вынесена из stream.rs трещоткой):
//! шифрует чанки синхронно (CPU) в pending и выгружает; адрес цели
//! уходит первым полезным payload-ом (first).

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::net::tcp::OwnedWriteHalf;

use crate::ss::aead::Method;
use crate::ss::frame::SsCodec;
use crate::ss::stream::eof;

/// Максимальный чанк payload.
const MAX_CHUNK: usize = 0x3FFF;
/// Тег AEAD.
const TAG: usize = 16;

/// Пишущая половина: шифрует чанки (синхронно, CPU) и выгружает.
pub struct SsWriteHalf {
    wr: OwnedWriteHalf,
    enc: SsCodec,
    /// Зашифрованные невыгруженные байты (накапливают несколько чанков).
    pending: Vec<u8>,
    sent: usize,
    /// Приписка к первому чанку (адрес цели — сторона клиента).
    first: Option<Vec<u8>>,
}

impl SsWriteHalf {
    /// Собрать половину; `first` — байты адреса цели (перед данными).
    #[must_use]
    pub fn new(wr: OwnedWriteHalf, method: Method, session: &[u8], first: Option<Vec<u8>>) -> Self {
        Self {
            wr,
            enc: SsCodec::new(crate::ss::aead::AeadBox::new(method, session)),
            pending: Vec::with_capacity(MAX_CHUNK + 2 * TAG),
            sent: 0,
            first,
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.sent < self.pending.len() {
            match Pin::new(&mut self.wr).poll_write(cx, &self.pending[self.sent..])? {
                Poll::Ready(0) => return Poll::Ready(Err(eof("SS: write вернул 0"))),
                Poll::Ready(n) => self.sent += n,
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SsWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        // Сначала выгрузить прошлые чанки (порядок байт строгий).
        if this.sent < this.pending.len() && this.drain(cx).is_pending() {
            return Poll::Pending;
        }
        // Принять не более одного чанка за вызов.
        let n = buf.len().min(MAX_CHUNK);
        let mut payload = Vec::with_capacity(this.first.as_ref().map_or(0, Vec::len) + n);
        if let Some(f) = this.first.take() {
            payload.extend_from_slice(&f);
        }
        payload.extend_from_slice(&buf[..n]);
        let chunk = this.enc.encrypt_chunk(&payload);
        this.pending.extend_from_slice(&chunk);
        match this.drain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.sent < this.pending.len() {
            if let Poll::Ready(e) = this.drain(cx) {
                e?;
            } else {
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.wr).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.sent < this.pending.len() {
            if let Poll::Ready(e) = this.drain(cx) {
                e?;
            } else {
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.wr).poll_shutdown(cx)
    }
}
