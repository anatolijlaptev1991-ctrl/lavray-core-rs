// SPDX-License-Identifier: GPL-3.0-only

//! AEAD-методы shadowsocks (2022-blake3-* и старые AEAD), нонс-счётчик и
//! диспетч-шифратор без dyn. Порт shadowsocks-rust (spec AEAD-2022).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

/// Метод shadowsocks (AEAD-семейство; legacy stream — хвост 7b+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20,
    Blake3Aes128,
    Blake3Aes256,
    Blake3Chacha20,
}

impl Method {
    /// Из строки протокола (None — неизвестный).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "xchacha20-ietf-poly1305" => Some(Self::Chacha20),
            "2022-blake3-aes-128-gcm" => Some(Self::Blake3Aes128),
            "2022-blake3-aes-256-gcm" => Some(Self::Blake3Aes256),
            "2022-blake3-chacha20-poly1305" => Some(Self::Blake3Chacha20),
            _ => None,
        }
    }

    /// Длина ключа (байт).
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Blake3Aes128 => 16,
            Self::Aes256Gcm | Self::Chacha20 | Self::Blake3Aes256 | Self::Blake3Chacha20 => 32,
        }
    }

    /// Длина соли (байт) — как ключ метода (spec AEAD-2022).
    #[must_use]
    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    /// 2022-семейство (subkey через HKDF, пароль = base64 ключа).
    #[must_use]
    pub fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Blake3Aes128 | Self::Blake3Aes256 | Self::Blake3Chacha20
        )
    }
}

/// 12-байтный нонс AEAD, инкремент little-endian с переносом.
#[derive(Clone)]
pub struct Nonce([u8; 12]);

impl Nonce {
    /// Нулевой (сессия начинается с 0).
    #[must_use]
    pub fn zero() -> Self {
        Self([0u8; 12])
    }

    /// +1 little-endian.
    pub fn increment(&mut self) {
        for b in self.0.iter_mut().rev() {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry {
                break;
            }
        }
    }

    /// Сырые байты.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Диспетч над AEAD (enum — без dyn/boxing-виртуализации на пакеты).
pub enum AeadBox {
    A128(Box<Aes128Gcm>),
    A256(Box<Aes256Gcm>),
    CC20(Box<ChaCha20Poly1305>),
}

impl AeadBox {
    /// Шифратор по методу и ключу (длина обязана быть key_len).
    #[must_use]
    pub fn new(method: Method, key: &[u8]) -> Self {
        let expect = "ключ длины метода (готовит ss::key)";
        match method {
            Method::Aes128Gcm | Method::Blake3Aes128 => {
                Self::A128(Box::new(Aes128Gcm::new_from_slice(key).expect(expect)))
            }
            Method::Aes256Gcm | Method::Blake3Aes256 => {
                Self::A256(Box::new(Aes256Gcm::new_from_slice(key).expect(expect)))
            }
            Method::Chacha20 | Method::Blake3Chacha20 => Self::CC20(Box::new(
                ChaCha20Poly1305::new_from_slice(key).expect(expect),
            )),
        }
    }

    /// Зашифровать (nonce уникален в рамках ключа).
    pub fn encrypt(&self, nonce: &Nonce, plain: &[u8]) -> aes_gcm::aead::Result<Vec<u8>> {
        let n = nonce.as_slice().into();
        match self {
            Self::A128(a) => a.encrypt(n, Payload::from(plain)),
            Self::A256(a) => a.encrypt(n, Payload::from(plain)),
            Self::CC20(a) => a.encrypt(n, Payload::from(plain)),
        }
    }

    /// Расшифровать.
    pub fn decrypt(&self, nonce: &Nonce, cipher: &[u8]) -> aes_gcm::aead::Result<Vec<u8>> {
        let n = nonce.as_slice().into();
        match self {
            Self::A128(a) => a.decrypt(n, Payload::from(cipher)),
            Self::A256(a) => a.decrypt(n, Payload::from(cipher)),
            Self::CC20(a) => a.decrypt(n, Payload::from(cipher)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_params() {
        let m = Method::parse("2022-blake3-aes-256-gcm").unwrap();
        assert!(m.is_2022());
        assert_eq!(m.key_len(), 32);
        assert_eq!(m.salt_len(), 32);
        let l = Method::parse("aes-128-gcm").unwrap();
        assert!(!l.is_2022() && l.key_len() == 16);
        assert!(Method::parse("rc4-md5").is_none());
    }

    #[test]
    fn nonce_increment_carries() {
        let mut n = Nonce::zero();
        for _ in 0..0x1_0000 {
            n.increment();
        }
        // Счётчик big-endian (правый байт младший — паритет shadowsocks
        // AEAD/TLS): 2^16 = 256^2 → единица в третьем справа байте.
        assert_eq!(&n.as_slice()[9..], &[1, 0, 0], "перенос через 2^16");
    }

    #[test]
    fn aead_roundtrip_each_method() {
        for m in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20,
            Method::Blake3Aes128,
            Method::Blake3Aes256,
            Method::Blake3Chacha20,
        ] {
            let key = vec![7u8; m.key_len()];
            let a = AeadBox::new(m, &key);
            let mut n = Nonce::zero();
            let ct = a.encrypt(&n, b"payload").expect("encrypt");
            assert_eq!(a.decrypt(&n, &ct).unwrap(), b"payload");
            n.increment();
            let ct2 = a.encrypt(&n, b"payload").unwrap();
            assert_ne!(ct, ct2, "nonce меняет шифротекст");
        }
    }
}
