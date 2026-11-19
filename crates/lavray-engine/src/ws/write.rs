// SPDX-License-Identifier: GPL-3.0-only

//! Пишущая половина ws (вынесена из frame.rs трещоткой): маскированные
//! бинарные фреймы ≤16 КиБ, случайная маска на фрейм.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::net::tcp::OwnedWriteHalf;

use crate::ws::frame::{MAX_CHUNK, op};

/// Пишущая половина ws: маскированные бинарные фреймы ≤MAX_CHUNK.
pub struct WsWriteHalf {
    wr: OwnedWriteHalf,
    /// Заголовок+маска+payload исходящего фрейма.
    out: Vec<u8>,
    sent: usize,
    first: Option<Vec<u8>>,
}

impl WsWriteHalf {
    #[must_use]
    pub fn new(wr: OwnedWriteHalf, first: Option<Vec<u8>>) -> Self {
        Self {
            wr,
            out: Vec::with_capacity(MAX_CHUNK + 14),
            sent: 0,
            first,
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.sent < self.out.len() {
            match Pin::new(&mut self.wr).poll_write(cx, &self.out[self.sent..])? {
                Poll::Ready(0) => return Poll::Ready(Err(std::io::Error::other("ws: write 0"))),
                Poll::Ready(n) => self.sent += n,
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for WsWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.sent < this.out.len() && this.drain(cx).is_pending() {
            return Poll::Pending;
        }
        let n = buf.len().min(MAX_CHUNK);
        let mut payload = Vec::with_capacity(this.first.as_ref().map_or(0, Vec::len) + n);
        if let Some(f) = this.first.take() {
            payload.extend_from_slice(&f);
        }
        payload.extend_from_slice(&buf[..n]);
        let len = payload.len();
        let mut out = vec![0x80 | op::BINARY];
        if len < 0x7E {
            out.push(0x80 | u8::try_from(len).unwrap_or(0x7D));
        } else if let Ok(v) = u16::try_from(len) {
            out.push(0x80 | 0x7E);
            out.extend_from_slice(&v.to_be_bytes());
        } else {
            out.push(0x80 | 0x7F);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mut mask = [0u8; 4];
        getrandom::fill(&mut mask).map_err(|e| std::io::Error::other(format!("ws mask: {e}")))?;
        out.extend_from_slice(&mask);
        let start = out.len();
        out.extend_from_slice(&payload);
        for (i, b) in out[start..].iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        this.out = out;
        match this.drain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.sent < this.out.len() {
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
        if this.sent < this.out.len() {
            if let Poll::Ready(e) = this.drain(cx) {
                e?;
            } else {
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.wr).poll_shutdown(cx)
    }
}
