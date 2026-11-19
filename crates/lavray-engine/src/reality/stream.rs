// SPDX-License-Identifier: GPL-3.0-only

//! RealityStream: канал application-данных TLS 1.3 (AsyncRead/AsyncWrite
//! поверх record-слоя с app-ключами; чтение — owned-future поверх half).

use crate::reality::kdf;
use crate::reality::record;
use crate::reality::record::{decrypt, read_record, write_encrypted};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

type ReadFut = Pin<
    Box<
        dyn std::future::Future<
                Output = (
                    tokio::io::ReadHalf<TcpStream>,
                    Result<(u8, [u8; 2], Vec<u8>), record::RecordError>,
                ),
            > + Send,
    >,
>;

/// Канал application-данных TLS 1.3.
pub struct RealityStream {
    read_half: Option<tokio::io::ReadHalf<TcpStream>>,
    write_half: tokio::io::WriteHalf<TcpStream>,
    c_ap: kdf::TrafficKeys,
    s_ap: kdf::TrafficKeys,
    read_seq: u64,
    write_seq: u64,
    buf: Vec<u8>,
    pos: usize,
    read_fut: Option<ReadFut>,
}
impl RealityStream {
    /// Собрать канал из половин TCP и app-ключей обеих сторон.
    pub(crate) fn new(
        read_half: Option<tokio::io::ReadHalf<TcpStream>>,
        write_half: tokio::io::WriteHalf<TcpStream>,
        c_ap: kdf::TrafficKeys,
        s_ap: kdf::TrafficKeys,
    ) -> Self {
        Self {
            read_half,
            write_half,
            c_ap,
            s_ap,
            read_seq: 0,
            write_seq: 0,
            buf: Vec::new(),
            pos: 0,
            read_fut: None,
        }
    }
}

impl AsyncRead for RealityStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos >= this.buf.len() {
            this.buf.clear();
            this.pos = 0;
            loop {
                if this.read_fut.is_none() {
                    let mut half = this
                        .read_half
                        .take()
                        .ok_or_else(|| io::Error::other("read half taken"))?;
                    // future ВЛАДЕЕТ half и возвращает его с результатом
                    this.read_fut = Some(Box::pin(async move {
                        let res = read_record(&mut half).await;
                        (half, res)
                    }));
                }
                let Some(fut) = this.read_fut.as_mut() else {
                    return Poll::Ready(Err(io::Error::other("no fut")));
                };
                let (returned_half, rec) = match fut.as_mut().poll(cx) {
                    Poll::Ready((h, Ok(v))) => {
                        this.read_fut = None;
                        (h, v)
                    }
                    Poll::Ready((h, Err(e))) => {
                        this.read_half = Some(h);
                        this.read_fut = None;
                        return Poll::Ready(Err(io::Error::other(e.0)));
                    }
                    Poll::Pending => return Poll::Pending,
                };
                this.read_half = Some(returned_half);
                let (rec_type, ver, payload) = rec;
                if rec_type == 21 {
                    return Poll::Ready(Err(io::Error::other("tls alert")));
                }
                if rec_type != 23 {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "unexpected record type {rec_type}"
                    ))));
                }
                let (inner, content) =
                    match decrypt(&this.s_ap, this.read_seq, rec_type, ver, &payload) {
                        Ok(v) => v,
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::other(e.0)));
                        }
                    };
                this.read_seq += 1;
                match inner {
                    // handshake-сообщения (4=NewSessionTicket, 8=KeyUpdate,
                    // 22=handshake, 24=KeyUpdate2) — не данные приложения
                    4 | 8 | 22 | 24 => {
                        continue;
                    }
                    21 => {
                        return Poll::Ready(Err(io::Error::other("tls alert")));
                    }
                    _ => {}
                }
                this.buf = content;
                break;
            }
        }
        let n = (this.buf.len() - this.pos).min(dst.remaining());
        dst.put_slice(&this.buf[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RealityStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        let mut half = Pin::new(&mut this.write_half);
        let poll_res = std::pin::pin!(write_encrypted(
            &mut half,
            &this.c_ap,
            this.write_seq,
            23,
            src
        ))
        .poll(cx);

        match poll_res {
            Poll::Ready(Ok(())) => {
                this.write_seq += 1;
                Poll::Ready(Ok(src.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.0))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().write_half), cx)
    }
}
