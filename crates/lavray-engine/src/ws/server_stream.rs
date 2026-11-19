// SPDX-License-Identifier: GPL-3.0-only

//! Серверная сторона ws (тесты): Upgrade-ответ 101, чтение маскированных
//! клиентских фреймов, запись немаскированных; WsServerStream =
//! AsyncRead+AsyncWrite для протоколов поверх (запись — server_write.rs).

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Принять Upgrade и вернуть фреймовый поток сервера.
pub async fn accept<S>(mut io: S) -> std::io::Result<WsServerStream<S>>
where
    S: AsyncReadExt + AsyncWrite + Unpin,
{
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        let n = io.read(&mut b).await?;
        if n == 0 {
            return Err(std::io::Error::other("ws-сервер: обрыв при upgrade"));
        }
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 8 * 1024 {
            return Err(std::io::Error::other("ws-сервер: upgrade >8 КиБ"));
        }
    }
    io.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
          Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
    )
    .await?;
    Ok(WsServerStream {
        io,
        hdr: [0u8; 14],
        pay: Vec::new(),
        pay_pos: 0,
        skip: 0,
        out: Vec::new(),
        sent: 0,
    })
}

/// Поток серверной стороны ws поверх S.
pub struct WsServerStream<S> {
    pub(super) io: S,
    pub(super) hdr: [u8; 14],
    pub(super) pay: Vec<u8>,
    pub(super) pay_pos: usize,
    pub(super) skip: usize,
    pub(super) out: Vec<u8>,
    pub(super) sent: usize,
}

impl<S> WsServerStream<S>
where
    S: AsyncReadExt + Unpin,
{
    /// Точно дочитать buf; Ok(false) — Pending.
    pub(super) fn fill(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<bool>> {
        let mut done = 0;
        while done < buf.len() {
            let mut rb = ReadBuf::new(&mut buf[done..]);
            match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Err(std::io::Error::other("ws-сервер: обрыв")));
                    }
                    done += rb.filled().len();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Ready(Ok(false)),
            }
        }
        Poll::Ready(Ok(true))
    }

    /// Дочитать pay целиком (по индексам — без двойного заёма).
    pub(super) fn fill_pay(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut done = 0;
        let total = self.pay.len();
        while done < total {
            let pay: &mut [u8] = &mut self.pay[..];
            let mut rb = ReadBuf::new(&mut pay[done..]);
            match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Err(std::io::Error::other("ws-сервер: обрыв")));
                    }
                    done += rb.filled().len();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Дочитать hdr[a..b] через локальный буфер (борроу-конфликт).
    pub(super) fn read_hdr(
        &mut self,
        cx: &mut Context<'_>,
        a: usize,
        b: usize,
    ) -> Poll<std::io::Result<()>> {
        let mut tmp = [0u8; 14];
        let room = b - a;
        match self.fill(cx, &mut tmp[..room]) {
            Poll::Ready(Ok(true)) => {}
            Poll::Ready(Ok(false)) | Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }
        self.hdr[a..b].copy_from_slice(&tmp[..room]);
        Poll::Ready(Ok(()))
    }
}
