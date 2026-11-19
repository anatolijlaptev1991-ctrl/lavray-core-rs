// SPDX-License-Identifier: GPL-3.0-only

//! Тело VMess (AEAD-блоки): блок = Seal(key, nonce с BE-счётчиком в
//! ПЕРВЫХ двух байтах, plaintext=[u16be(len)][data]) → провод
//! [u16be(len)][sealed]. Чанк ≤15000 (WriteChunkSize sing-vmess).

use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::Aes128Gcm as Aes128GcmG;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::generic_array::GenericArray;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::tcp::OwnedReadHalf;

use crate::vmess::header::Security;
use crate::vmess::kdf::chacha_key;

/// Максимальный чанк тела.
pub const CHUNK: usize = 15000;
/// Тег AEAD.
pub const TAG: usize = 16;

/// AEAD тела по security.
pub(super) enum BodyAead {
    Aes(Box<aes_gcm::Aes128Gcm>),
    Chacha(Box<chacha20poly1305::ChaCha20Poly1305>),
}

impl BodyAead {
    pub(super) fn new(security: Security, key16: &[u8; 16]) -> Self {
        match security {
            Security::Aes128Gcm => Self::Aes(Box::new(
                Aes128GcmG::new_from_slice(key16).expect("16 байт"),
            )),
            Security::Chacha20Poly1305 => Self::Chacha(Box::new(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(&chacha_key(key16))
                    .expect("32 байта"),
            )),
        }
    }

    pub(super) fn seal(&self, nonce: &[u8; 12], pt: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::Aead;
        match self {
            Self::Aes(a) => a
                .encrypt(GenericArray::from_slice(nonce), pt)
                .expect("nonce уникален"),
            Self::Chacha(a) => a
                .encrypt(GenericArray::from_slice(nonce), pt)
                .expect("nonce уникален"),
        }
    }

    fn open(&self, nonce: &[u8; 12], ct: &[u8]) -> aes_gcm::aead::Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        match self {
            Self::Aes(a) => a.decrypt(GenericArray::from_slice(nonce), ct),
            Self::Chacha(a) => a.decrypt(GenericArray::from_slice(nonce), ct),
        }
    }
}

/// Нонс-счётчик: base с BE-счётчиком в первых 2 байтах (AEADWriter).
#[derive(Clone)]
pub(crate) struct NonceCounter {
    base: [u8; 12],
    count: u16,
}

impl NonceCounter {
    pub(crate) fn new(base16: &[u8; 16]) -> Self {
        let mut b = [0u8; 12];
        b.copy_from_slice(&base16[..12]);
        Self { base: b, count: 0 }
    }

    pub(super) fn next(&mut self) -> [u8; 12] {
        let mut n = self.base;
        n[0] = u8::try_from(self.count >> 8).unwrap_or(0);
        n[1] = u8::try_from(self.count & 0xFF).unwrap_or(0);
        self.count = self.count.wrapping_add(1);
        n
    }
}

pub struct BodyReader {
    rd: OwnedReadHalf,
    aead: BodyAead,
    nonce: NonceCounter,
    plain: Vec<u8>,
    pos: usize,
}

impl BodyReader {
    /// Собрать из половины и ключей тела.
    #[must_use]
    pub fn new(
        rd: OwnedReadHalf,
        security: Security,
        key16: &[u8; 16],
        nonce16: &[u8; 16],
    ) -> Self {
        Self {
            rd,
            aead: BodyAead::new(security, key16),
            nonce: NonceCounter::new(nonce16),
            plain: Vec::new(),
            pos: 0,
        }
    }

    fn read_exact_into(
        &mut self,
        cx: &mut Context<'_>,
        want: usize,
        buf: &mut Vec<u8>,
    ) -> Poll<std::io::Result<()>> {
        while buf.len() < want {
            let mut tmp = [0u8; CHUNK + 2 + TAG];
            let room = want - buf.len();
            let mut rb = ReadBuf::new(&mut tmp[..room]); // не съесть лишнее
            match Pin::new(&mut self.rd).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Err(std::io::Error::other("vmess: обрыв блока")));
                    }
                    buf.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for BodyReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pos < this.plain.len() {
                let n = (this.plain.len() - this.pos).min(buf.remaining());
                let from = this.pos;
                buf.put_slice(&this.plain[from..from + n]);
                this.pos += n;
                return Poll::Ready(Ok(()));
            }
            // Наружная длина — размер sealed (метка plaintext — внутри).
            let mut head2 = Vec::with_capacity(2);
            if let Poll::Ready(e) = this.read_exact_into(cx, 2, &mut head2) {
                e?;
            } else {
                return Poll::Pending;
            }
            let sealed_len = u16::from_be_bytes([head2[0], head2[1]]) as usize;
            if !(2 + TAG..=CHUNK + 2 + TAG).contains(&sealed_len) {
                return Poll::Ready(Err(std::io::Error::other("vmess: плохая длина блока")));
            }
            let mut sealed = Vec::with_capacity(sealed_len);
            if let Poll::Ready(e) = this.read_exact_into(cx, sealed_len, &mut sealed) {
                e?;
            } else {
                return Poll::Pending;
            }
            let plain = this
                .aead
                .open(&this.nonce.next(), &sealed)
                .map_err(|_| std::io::Error::other("vmess: тег блока не сошёлся"))?;
            // plaintext = [dataLen][data] — пропускаем метку.
            this.plain = plain;
            this.pos = 2;
        }
    }
}
