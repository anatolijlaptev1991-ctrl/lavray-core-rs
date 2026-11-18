// SPDX-License-Identifier: GPL-3.0-only

//! Потоковые половины SS-туннеля: безопасные state-machine реализации
//! AsyncRead/AsyncWrite поверх чанкового фрейма (без unsafe и
//! box-фьючерсов). Читающая — шаги [len][payload] с переиспользуемым
//! буфером; пишущая — синхронное шифрование в pending + выгрузка.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::tcp::OwnedReadHalf;

use crate::ss::aead::Method;
use crate::ss::frame::{SsCodec, TAG};

/// Максимальный чанк payload.
const MAX_CHUNK: usize = 0x3FFF;

/// Читающая половина: расшифровывает чанки.
pub struct SsReadHalf {
    rd: OwnedReadHalf,
    dec: SsCodec,
    /// Заголовок длины (2+TAG), переиспользуется.
    len_hdr: Box<[u8; SsCodec::LEN_FRAME]>,
    /// Буфер payload (MAX+TAG), переиспользуется.
    pay: Box<[u8]>,
    /// Ожидаемая длина payload (0 — ждём заголовок следующего чанка).
    want: usize,
    filled: usize,
    /// Расшифрованный неотданный остаток.
    plain: Vec<u8>,
    plain_pos: usize,
}

impl SsReadHalf {
    /// Собрать половину из готового сессионного ключа.
    #[must_use]
    pub fn new(rd: OwnedReadHalf, method: Method, session: &[u8]) -> Self {
        Self {
            rd,
            dec: SsCodec::new(crate::ss::aead::AeadBox::new(method, session)),
            len_hdr: Box::new([0u8; SsCodec::LEN_FRAME]),
            pay: vec![0u8; MAX_CHUNK + TAG].into_boxed_slice(),
            want: 0,
            filled: 0,
            plain: Vec::new(),
            plain_pos: 0,
        }
    }
}

impl AsyncRead for SsReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1) Отдать расшифрованный остаток.
            if this.plain_pos < this.plain.len() {
                let n = (this.plain.len() - this.plain_pos).min(buf.remaining());
                let from = this.plain_pos;
                buf.put_slice(&this.plain[from..from + n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            // 2) Заголовок длины следующего чанка.
            if this.want == 0 {
                let hdr: &mut [u8] = &mut this.len_hdr[..];
                let mut done = this.filled;
                while done < hdr.len() {
                    let mut rb = ReadBuf::new(&mut hdr[done..]);
                    // Poll<Result> через `?` разворачивает только уровень Poll:
                    // Ready(Err) молча выбрасывался — явный match обязателен.
                    match Pin::new(&mut this.rd).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    if rb.filled().is_empty() {
                        eprintln!("POLL-RD: underlying EOF done={} want={}", done, this.want);
                        return if done == 0 {
                            Poll::Ready(Ok(())) // чистый EOF между чанками
                        } else {
                            Poll::Ready(Err(eof("SS: обрыв в заголовке чанка")))
                        };
                    }
                    done += rb.filled().len();
                }
                this.filled = 0;
                this.want = this
                    .dec
                    .decrypt_len(&hdr[..])
                    .map_err(|_| proto("SS: тег заголовка не сошёлся"))?;
                continue;
            }
            // 3) Payload чанка.
            let need = this.want + TAG;
            {
                let pay: &mut [u8] = &mut this.pay[..];
                let mut done = this.filled;
                while done < need {
                    let mut rb = ReadBuf::new(&mut pay[done..need]);
                    match Pin::new(&mut this.rd).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    if rb.filled().is_empty() {
                        return Poll::Ready(Err(eof("SS: обрыв в payload чанка")));
                    }
                    done += rb.filled().len();
                }
            }
            let plain = this
                .dec
                .decrypt_payload(this.want, &this.pay[..need])
                .map_err(|_| proto("SS: тег payload не сошёлся"))?;
            this.plain = plain;
            this.plain_pos = 0;
            this.want = 0;
            this.filled = 0;
        }
    }
}

pub(super) fn eof(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, msg.to_string())
}

fn proto(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}
