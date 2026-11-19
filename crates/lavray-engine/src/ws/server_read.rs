// SPDX-License-Identifier: GPL-3.0-only

//! Чтение серверной стороны ws (вынесено из server_stream.rs трещоткой):
//! МАСКИРОВАННЫЕ клиентские фреймы — размаскировать и отдать payload.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use super::server_stream::WsServerStream;

impl<S> AsyncRead for WsServerStream<S>
where
    S: AsyncReadExt + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pay_pos < this.pay.len() {
                let n = (this.pay.len() - this.pay_pos).min(buf.remaining());
                let from = this.pay_pos;
                buf.put_slice(&this.pay[from..from + n]);
                this.pay_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.skip > 0 {
                let mut trash = [0u8; 512];
                let want = this.skip.min(trash.len());
                match this.fill(cx, &mut trash[..want]) {
                    Poll::Ready(Ok(true)) => this.skip -= want,
                    Poll::Ready(Ok(false)) | Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
                continue;
            }
            match this.read_hdr(cx, 0, 2) {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
            let opcode = this.hdr[0] & 0x0F;
            let masked = this.hdr[1] & 0x80 != 0;
            let mut len = u64::from(this.hdr[1] & 0x7F);
            if len == 126 {
                match this.read_hdr(cx, 2, 4) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
                len = u64::from(u16::from_be_bytes([this.hdr[2], this.hdr[3]]));
            } else if len == 127 {
                match this.read_hdr(cx, 2, 10) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&this.hdr[2..10]);
                len = u64::from_be_bytes(b);
            }
            let mut mask = [0u8; 4];
            if masked {
                match this.read_hdr(cx, 10, 14) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
                mask.copy_from_slice(&this.hdr[10..14]);
            }
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            if len > crate::ws::frame::MAX_FRAME {
                return Poll::Ready(Err(std::io::Error::other("ws-сервер: фрейм велик")));
            }
            this.pay = vec![0u8; len];
            this.pay_pos = 0;
            if len > 0 {
                match this.fill_pay(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
            if masked {
                for (i, b) in this.pay.iter_mut().enumerate() {
                    *b ^= mask[i % 4];
                }
            }
            match opcode {
                0x8 => return Poll::Ready(Ok(())), // close → EOF
                0x9 | 0xA => {
                    this.skip = len;
                    this.pay.clear();
                }
                _ => {}
            }
        }
    }
}
