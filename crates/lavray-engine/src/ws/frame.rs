// SPDX-License-Identifier: GPL-3.0-only

//! Фреймы WebSocket (RFC 6455): запись ТОЛЬКО маскированными фреймами,
//! чтение немаскированных серверных; Close — EOF, Ping/Pong — пропуск.
//! Без unsafe, state-machine по схеме vmess/body.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::tcp::OwnedReadHalf;

/// Максимальный payload одного фрейма записи.
pub const MAX_CHUNK: usize = 16 * 1024;
/// Стандартный лимит фрейма от сервера (1 МиБ).
pub const MAX_FRAME: usize = 1 << 20;
/// Опкоды.
pub(crate) mod op {
    pub const CONT: u8 = 0x0;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// Читающая половина ws: серверные фреймы (маска отсутствует).
pub struct WsReadHalf {
    rd: OwnedReadHalf,
    /// Заголовок фрейма (2 обязательных + до 8 длины + 4 маски).
    hdr: Box<[u8; 14]>,
    /// Payload текущего фрейма (бинарный/cont) — отдаётся частями.
    pay: Vec<u8>,
    pay_pos: usize,
    /// Пропускаемый payload (ping/pong) — остаток.
    skip: usize,
}

impl WsReadHalf {
    #[must_use]
    pub fn new(rd: OwnedReadHalf) -> Self {
        Self {
            rd,
            hdr: Box::new([0u8; 14]),
            pay: Vec::new(),
            pay_pos: 0,
            skip: 0,
        }
    }

    /// Дочитать внешний буфер (пропуск ping).
    fn fill4(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<std::io::Result<bool>> {
        let mut done = 0;
        while done < buf.len() {
            let mut rb = ReadBuf::new(&mut buf[done..]);
            match Pin::new(&mut self.rd).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Err(std::io::Error::other("ws: обрыв")));
                    }
                    done += rb.filled().len();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Ready(Ok(false)),
            }
        }
        Poll::Ready(Ok(true))
    }

    /// Точно дочитать hdr[a..b]; Ready(Ok(true)) — готово, Ready(Ok(false))
    /// — Pending (будет перезапрошено).
    fn fill2(&mut self, cx: &mut Context<'_>, a: usize, b: usize) -> Poll<std::io::Result<bool>> {
        let mut done = a;
        while done < b {
            let hdr: &mut [u8] = &mut self.hdr[..];
            let mut rb = ReadBuf::new(&mut hdr[done..b]);
            match Pin::new(&mut self.rd).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Err(std::io::Error::other("ws: обрыв")));
                    }
                    done += rb.filled().len();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Ready(Ok(false)),
            }
        }
        Poll::Ready(Ok(true))
    }

    /// Точно дочитать pay[..n].
    fn fill3(&mut self, cx: &mut Context<'_>, n: usize) -> Poll<std::io::Result<bool>> {
        let mut done = 0;
        while done < n {
            let pay: &mut [u8] = &mut self.pay[..];
            let mut rb = ReadBuf::new(&mut pay[done..n]);
            match Pin::new(&mut self.rd).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Err(std::io::Error::other("ws: обрыв")));
                    }
                    done += rb.filled().len();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Ready(Ok(false)),
            }
        }
        Poll::Ready(Ok(true))
    }
}

impl AsyncRead for WsReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1) Остаток payload — отдать.
            if this.pay_pos < this.pay.len() {
                let n = (this.pay.len() - this.pay_pos).min(buf.remaining());
                let from = this.pay_pos;
                buf.put_slice(&this.pay[from..from + n]);
                this.pay_pos += n;
                return Poll::Ready(Ok(()));
            }
            // 2) Пропуск ping/pong.
            if this.skip > 0 {
                let mut trash = [0u8; 512];
                let want = this.skip.min(trash.len());
                match this.fill4(cx, &mut trash[..want]) {
                    Poll::Ready(Ok(true)) => this.skip -= want,
                    Poll::Ready(Ok(false)) | Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
                continue;
            }
            // 3) Заголовок следующего фрейма.
            match this.fill2(cx, 0, 2) {
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) | Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
            let opcode = this.hdr[0] & 0x0F;
            if this.hdr[1] & 0x80 != 0 {
                // RFC 5.5: сервер НЕ маскирует фреймы клиенту.
                return Poll::Ready(Err(std::io::Error::other("ws: сервер прислал маску")));
            }
            let mut len = u64::from(this.hdr[1] & 0x7F);
            if len == 126 {
                match this.fill2(cx, 2, 4) {
                    Poll::Ready(Ok(true)) => {}
                    Poll::Ready(Ok(false)) | Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
                len = u64::from(u16::from_be_bytes([this.hdr[2], this.hdr[3]]));
            } else if len == 127 {
                match this.fill2(cx, 2, 10) {
                    Poll::Ready(Ok(true)) => {}
                    Poll::Ready(Ok(false)) | Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&this.hdr[2..10]);
                len = u64::from_be_bytes(b);
            }
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            match opcode {
                op::BINARY | op::CONT => {
                    if len > MAX_FRAME {
                        return Poll::Ready(Err(std::io::Error::other(format!(
                            "ws: фрейм {len} байт > лимита {MAX_FRAME}"
                        ))));
                    }
                    this.pay = vec![0u8; len];
                    this.pay_pos = 0;
                    // 4) Дочитать payload фрейма целиком (payload ≤1 МиБ —
                    // буфер фрейма; для отдачи частями достаточно).
                    if len > 0 {
                        let n = len;
                        match this.fill3(cx, n) {
                            Poll::Ready(Ok(true)) => {}
                            Poll::Ready(Ok(false)) | Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        }
                    }
                }
                op::CLOSE => return Poll::Ready(Ok(())), // EOF
                op::PING | op::PONG => {
                    this.skip = len;
                }
                other => {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "ws: опкод {other:#04x}"
                    ))));
                }
            }
        }
    }
}
