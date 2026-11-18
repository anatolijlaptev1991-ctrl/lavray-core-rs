// SPDX-License-Identifier: GPL-3.0-only

//! Фрейм AEAD-shadowsocks: [salt][чанки], чанк = enc(len_be16)+tag,
//! enc(payload≤0x3FFF)+tag; нонс-счётчик общий, +1 на каждую операцию.
//! Первый чанк полезной нагрузки — адрес цели (SOCKS5-формат). Порт
//! shadowsocks-rust (spec AEAD-2022).

use crate::ss::aead::{AeadBox, Nonce};

/// Тег AEAD (GCM/Poly1305 = 16).
pub const TAG: usize = 16;
/// Максимум полезной нагрузки чанка.
pub const MAX_CHUNK: usize = 0x3FFF;

/// Кодек направления (шифрует/расшифровывает чанки, ведёт нонс).
pub struct SsCodec {
    aead: AeadBox,
    nonce: Nonce,
}

impl SsCodec {
    /// Кодек на сессионном ключе (нонс с нуля).
    #[must_use]
    pub fn new(aead: AeadBox) -> Self {
        Self {
            aead,
            nonce: Nonce::zero(),
        }
    }

    /// Зашифровать чанк: [enc(len)|tag][enc(payload)|tag] одним blob-ом.
    pub fn encrypt_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        debug_assert!(payload.len() <= MAX_CHUNK);
        debug_assert!(payload.len() <= MAX_CHUNK);
        let len = u16::try_from(payload.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes();
        let mut out = Vec::with_capacity(2 + TAG + payload.len() + TAG);
        out.extend_from_slice(
            &self
                .aead
                .encrypt(&self.nonce, &len)
                .expect("nonce уникален"),
        );
        self.nonce.increment();
        out.extend_from_slice(
            &self
                .aead
                .encrypt(&self.nonce, payload)
                .expect("nonce уникален"),
        );
        self.nonce.increment();
        out
    }

    /// Размер заголовка длины (шифротекст + тег).
    pub const LEN_FRAME: usize = 2 + TAG;

    /// Расшифровать длину из шифротекста заголовка (2+TAG байт).
    pub fn decrypt_len(&mut self, frame: &[u8]) -> aes_gcm::aead::Result<usize> {
        let plain = self.aead.decrypt(&self.nonce, frame)?;
        self.nonce.increment();
        let n = u16::from_be_bytes([plain[0], plain[1]]) as usize;
        if n == 0 || n > MAX_CHUNK {
            return Err(aes_gcm::aead::Error);
        }
        Ok(n)
    }

    /// Расшифровать полезную нагрузку (n+TAG байт).
    pub fn decrypt_payload(&mut self, n: usize, frame: &[u8]) -> aes_gcm::aead::Result<Vec<u8>> {
        let plain = self.aead.decrypt(&self.nonce, frame)?;
        self.nonce.increment();
        if plain.len() != n {
            return Err(aes_gcm::aead::Error);
        }
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ss::aead::Method;
    use crate::ss::key::{identity_key, session_key};

    fn codec(method: Method) -> (SsCodec, SsCodec) {
        let id = identity_key(method, "test");
        let salt = vec![1u8; method.salt_len()];
        let k = session_key(method, &id, &salt);
        (
            SsCodec::new(AeadBox::new(method, &k)),
            SsCodec::new(AeadBox::new(method, &k)),
        )
    }

    #[test]
    fn chunk_roundtrip_all_methods() {
        for m in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20,
            Method::Blake3Aes128,
            Method::Blake3Aes256,
            Method::Blake3Chacha20,
        ] {
            let (mut c, mut d) = codec(m);
            let blob = c.encrypt_chunk(b"hello world");
            let n = d.decrypt_len(&blob[..SsCodec::LEN_FRAME]).unwrap();
            assert_eq!(n, 11);
            let pay = d.decrypt_payload(n, &blob[SsCodec::LEN_FRAME..]).unwrap();
            assert_eq!(pay, b"hello world");
        }
    }

    #[test]
    fn nonce_sequence_multiple_chunks() {
        let (mut c, mut d) = codec(Method::Blake3Aes256);
        for i in 0..5u8 {
            let blob = c.encrypt_chunk(&[i; 100]);
            let n = d.decrypt_len(&blob[..SsCodec::LEN_FRAME]).unwrap();
            assert_eq!(n, 100);
            assert_eq!(
                d.decrypt_payload(n, &blob[SsCodec::LEN_FRAME..]).unwrap(),
                vec![i; 100]
            );
        }
    }

    #[test]
    fn tampered_len_fails() {
        let (mut c, mut d) = codec(Method::Aes256Gcm);
        let mut blob = c.encrypt_chunk(b"data");
        blob[0] ^= 0xFF;
        assert!(d.decrypt_len(&blob[..SsCodec::LEN_FRAME]).is_err());
    }
}
