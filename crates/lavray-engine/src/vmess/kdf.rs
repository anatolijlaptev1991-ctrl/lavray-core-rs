// SPDX-License-Identifier: GPL-3.0-only

//! Ключи VMess (порт sing-vmess kdf.go/protocol.go): userKey из UUID,
//! KDF — вложенный HMAC-SHA256 ("VMess AEAD KDF" → salt), производные
//! ключи AEAD-заголовков по authId+nonce.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Соли KDF (protocol.go sing-vmess).
pub mod salt {
    pub const AUTH_ID_ENC: &str = "AES Auth ID Encryption";
    pub const HDR_LEN_KEY: &str = "VMess Header AEAD Key_Length";
    pub const HDR_LEN_NONCE: &str = "VMess Header AEAD Nonce_Length";
    pub const HDR_KEY: &str = "VMess Header AEAD Key";
    pub const HDR_NONCE: &str = "VMess Header AEAD Nonce";
    pub const RESP_LEN_KEY: &str = "AEAD Resp Header Len Key";
    pub const RESP_LEN_NONCE: &str = "AEAD Resp Header Len IV";
    pub const RESP_KEY: &str = "AEAD Resp Header Key";
    pub const RESP_NONCE: &str = "AEAD Resp Header IV";
}

/// Ключ пользователя: MD5(uuid16 || "c48619fe-…").
#[must_use]
pub fn user_key(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(uuid_bytes);
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.finalize().into()
}

/// KDF(key, salt, path…): хеш-цепочка hMacCreator из sing-vmess — каждый
/// элемент [salt, path…] — КЛЮЧ очередного вложенного HMAC (хеш-функция
/// которого — предыдущий слой; корень SHA-256); вход `key` — сообщение
/// верхнего слоя. out = H_[salt,path…](key).
#[must_use]
pub fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> Vec<u8> {
    // Корень цепочки: HMAC-SHA256 с ключом "VMess AEAD KDF".
    let mut hf: HashFn = Box::new(|m: &[u8]| hmac_sha256(b"VMess AEAD KDF", m));
    for v in std::iter::once(salt.as_bytes()).chain(path.iter().copied()) {
        let k = v.to_vec();
        let prev = hf;
        hf = Box::new(move |m: &[u8]| hmac_with_hash(prev.as_ref(), &k, m));
    }
    hf(key)
}

/// Хеш-функция цепочки KDF.
type HashFn = Box<dyn Fn(&[u8]) -> Vec<u8>>;

/// Обычный HMAC-SHA256.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC принимает любой размер ключа");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

/// HMAC с произвольной «хеш-функцией» h (блок 64, выход 32):
/// h(k⊕opad ‖ h(k⊕ipad ‖ msg)).
fn hmac_with_hash(h: &dyn Fn(&[u8]) -> Vec<u8>, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut k = key.to_vec();
    if k.len() > 64 {
        k = h(&k);
    }
    k.resize(64, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5C).collect();
    let mut inner = ipad;
    inner.extend_from_slice(msg);
    let digest = h(&inner);
    let mut outer = opad;
    outer.extend_from_slice(&digest);
    h(&outer)
}

/// AES-128-ECB шифрование одного блока (AuthID).
pub fn aes_ecb_encrypt_block(key16: &[u8], block: &mut [u8; 16]) {
    let cipher = Aes128::new_from_slice(key16).expect("16 байт");
    cipher.encrypt_block(block.into());
}

/// AES-128-ECB расшифровка одного блока (тест-сервер).
pub fn aes_ecb_decrypt_block(key16: &[u8], block: &mut [u8; 16]) {
    let cipher = Aes128::new_from_slice(key16).expect("16 байт");
    cipher.decrypt_block(block.into());
}

/// SHA-256[..16].
#[must_use]
pub fn sha256_16(data: &[u8]) -> [u8; 16] {
    let d = Sha256::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// Chacha20-ключ VMess: md5-цепочка до 32 байт (GenerateChacha20Poly1305Key).
#[must_use]
pub fn chacha_key(b: &[u8]) -> [u8; 32] {
    use md5::{Digest, Md5};
    let mut key = [0u8; 32];
    let first: [u8; 16] = Md5::digest(b).into();
    key[..16].copy_from_slice(&first);
    let second: [u8; 16] = Md5::digest(&key[..16]).into();
    key[16..].copy_from_slice(&second);
    key
}

/// fnv-1a 32 бита (хэш заголовка).
#[must_use]
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C_9DC5;
    for b in data {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_matches_go_reference() {
        // Эталоны из sing-vmess v0.2.8 (go run, 19.11).
        let a = kdf(
            b"0123456789abcdef",
            "VMess Header AEAD Key_Length",
            &[b"AAAABBBBCCCCDDDD", b"nonce8xx"],
        );
        assert_eq!(
            hex(&a),
            "fb3bafab0e61ef9fcb09dd9e4962492282d7c271a25b2374bd539ff3410b7696"
        );
        let b_ = kdf(b"0123456789abcdef", "AES Auth ID Encryption", &[]);
        assert_eq!(
            hex(&b_),
            "ebde3a0b17bf94c86fa140917ec6a0c9773a777693a18a40bb09b38fb9b0b816"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter()
            .fold(String::with_capacity(b.len() * 2), |mut acc, x| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{x:02x}");
                acc
            })
    }

    #[test]
    fn kdf_stable_layers() {
        let a = kdf(b"k", salt::HDR_KEY, &[b"auth", b"nonce"]);
        let b_ = kdf(b"k", salt::HDR_KEY, &[b"auth", b"noece"]);
        assert_eq!(a.len(), 32);
        assert_ne!(a, b_);
        assert_eq!(a, kdf(b"k", salt::HDR_KEY, &[b"auth", b"nonce"]));
    }

    #[test]
    fn ecb_roundtrip_block() {
        let k = [7u8; 16];
        let orig = [1u8; 16];
        let mut b = orig;
        aes_ecb_encrypt_block(&k, &mut b);
        assert_ne!(b, orig);
        aes_ecb_decrypt_block(&k, &mut b);
        assert_eq!(b, orig);
    }

    #[test]
    fn fnv_vector() {
        // fnv1a32("") = 0x811c9dc5; "a" = 0xe40c292c.
        assert_eq!(fnv1a32(b""), 0x811C_9DC5);
        assert_eq!(fnv1a32(b"a"), 0xE40C_292C);
    }
}
