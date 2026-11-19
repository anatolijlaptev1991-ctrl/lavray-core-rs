// SPDX-License-Identifier: GPL-3.0-only

//! Запись серверной стороны ws (вынесено из server_stream.rs трещоткой):
//! НЕмаскированные фреймы ≤16 КиБ (RFC 6455: сервер не маскирует).

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

use super::frame::MAX_CHUNK;
use super::server_stream::WsServerStream;

impl<S> AsyncWrite for WsServerStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.sent < this.out.len() && drain(this, cx).is_pending() {
            return Poll::Pending;
        }
        let n = buf.len().min(MAX_CHUNK);
        let mut out = vec![0x82]; // FIN|BINARY, сервер НЕ маскирует
        if n < 0x7E {
            out.push(u8::try_from(n).unwrap_or(0x7D));
        } else {
            out.push(0x7E);
            out.extend_from_slice(&u16::try_from(n).unwrap_or(0).to_be_bytes());
        }
        out.extend_from_slice(&buf[..n]);
        this.out = out;
        this.sent = 0;
        match drain(this, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.sent < this.out.len() {
            if let Poll::Ready(e) = drain(this, cx) {
                e?;
            } else {
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.sent < this.out.len() {
            if let Poll::Ready(e) = drain(this, cx) {
                e?;
            } else {
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

/// Выгрузить this.out[..] в io.
fn drain<S>(this: &mut WsServerStream<S>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
where
    S: AsyncWrite + Unpin,
{
    while this.sent < this.out.len() {
        match Pin::new(&mut this.io).poll_write(cx, &this.out[this.sent..])? {
            Poll::Ready(0) => return Poll::Ready(Err(std::io::Error::other("ws-сервер: write 0"))),
            Poll::Ready(n) => this.sent += n,
            Poll::Pending => return Poll::Pending,
        }
    }
    this.out.clear();
    this.sent = 0;
    Poll::Ready(Ok(()))
}
