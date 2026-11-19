// SPDX-License-Identifier: GPL-3.0-only

//! Пишущая половина тела VMess (вынесена из body.rs трещоткой).

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::net::tcp::OwnedWriteHalf;

use crate::vmess::body::{BodyAead, CHUNK, NonceCounter, TAG};
use crate::vmess::header::Security;

/// Пишущая половина тела.
pub struct BodyWriter {
    wr: OwnedWriteHalf,
    aead: BodyAead,
    nonce: NonceCounter,
    pending: Vec<u8>,
    sent: usize,
    first: Option<Vec<u8>>,
}

impl BodyWriter {
    /// Собрать; `first` — приписка к первому блоку.
    #[must_use]
    pub fn new(
        wr: OwnedWriteHalf,
        security: Security,
        key16: &[u8; 16],
        nonce16: &[u8; 16],
        first: Option<Vec<u8>>,
    ) -> Self {
        Self {
            wr,
            aead: BodyAead::new(security, key16),
            nonce: NonceCounter::new(nonce16),
            pending: Vec::with_capacity(CHUNK + 2 + TAG),
            sent: 0,
            first,
        }
    }
}

impl AsyncWrite for BodyWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.sent < this.pending.len() && this.drain(cx).is_pending() {
            return Poll::Pending;
        }
        let n = buf.len().min(CHUNK);
        let mut pt = Vec::with_capacity(this.first.as_ref().map_or(0, Vec::len) + 2 + n);
        if let Some(f) = this.first.take() {
            pt.extend_from_slice(&f);
        }
        // Метка = длина ДАННЫХ (без самой метки — паритет StreamChunkWriter),
        // включая first-приписку.
        let len = u16::try_from(pt.len() + n).unwrap_or(u16::MAX);
        pt.splice(0..0, len.to_be_bytes()); // [len][data] внутри plaintext
        pt.extend_from_slice(&buf[..n]);
        let sealed = this.aead.seal(&this.nonce.next(), &pt);
        // Провод (StreamChunkWriter СНАРУЖИ AEADWriter): [BE16(len(sealed))][sealed].
        let wire_len = u16::try_from(sealed.len()).unwrap_or(u16::MAX);
        this.pending.extend_from_slice(&wire_len.to_be_bytes());
        this.pending.extend_from_slice(&sealed);
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

impl BodyWriter {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.sent < self.pending.len() {
            match Pin::new(&mut self.wr).poll_write(cx, &self.pending[self.sent..])? {
                Poll::Ready(0) => return Poll::Ready(Err(std::io::Error::other("vmess: write 0"))),
                Poll::Ready(n) => self.sent += n,
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}
