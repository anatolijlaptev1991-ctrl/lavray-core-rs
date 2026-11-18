// SPDX-License-Identifier: GPL-3.0-only

//! Ключи shadowsocks: пароль → identity-ключ (2022: blake3, старые AEAD:
//! EVP_BytesToKey/MD5) и сессионный subkey (HKDF-SHA256 с salt
//! "ss-subkey"||server_salt — только 2022). Порт shadowsocks-rust.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::ss::aead::Method;

/// Identity-ключ метода из пароля (длина = key_len метода).
#[must_use]
pub fn identity_key(method: Method, password: &str) -> Vec<u8> {
    let len = method.key_len();
    if method.is_2022() {
        // 2022: пароль — base64 ключа; blake3-XOF добивает до длины метода
        // (некорректная длина пароля — не ошибка ядра, парирует XOF).
        let mut out = vec![0u8; len];
        blake3::Hasher::new()
            .update(password.as_bytes())
            .finalize_xof()
            .fill(&mut out);
        out
    } else {
        evp_bytes_to_key(password.as_bytes(), len)
    }
}

/// Сессионный ключ: 2022 — HKDF-SHA256("ss-subkey"||salt, identity);
/// старые AEAD шифруют самим identity-ключом.
#[must_use]
pub fn session_key(method: Method, identity: &[u8], server_salt: &[u8]) -> Vec<u8> {
    if !method.is_2022() {
        return identity.to_vec();
    }
    let mut salt = Vec::with_capacity(11 + server_salt.len());
    salt.extend_from_slice(b"ss-subkey");
    salt.extend_from_slice(server_salt);
    let hk = Hkdf::<Sha256>::new(Some(&salt), identity);
    let mut out = vec![0u8; method.key_len()];
    hk.expand(b"ss-subkey", &mut out)
        .expect("длина ключа метода допустима для HKDF");
    out
}

/// EVP_BytesToKey (OpenSSL, MD5, без соли): цепочка MD5 до нужной длины.
fn evp_bytes_to_key(password: &[u8], len: usize) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut out = Vec::with_capacity(len);
    let mut prev: Option<Vec<u8>> = None;
    while out.len() < len {
        let mut h = Md5::new();
        if let Some(p) = &prev {
            h.update(p);
        }
        h.update(password);
        let d = h.finalize().to_vec();
        out.extend_from_slice(&d);
        prev = Some(d);
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_bytes_to_key_known_length() {
        let a = evp_bytes_to_key(b"pass", 32);
        assert_eq!(a.len(), 32);
        assert_ne!(a, evp_bytes_to_key(b"pass2", 32));
        assert_eq!(a, evp_bytes_to_key(b"pass", 32), "детерминизм");
    }

    #[test]
    fn session_key_2022_differs_by_salt() {
        let m = Method::Blake3Aes256;
        let id = identity_key(m, "test-key");
        let k1 = session_key(m, &id, b"1234567890abcdef");
        let k2 = session_key(m, &id, b"fedcba9876543210");
        assert_eq!(k1.len(), 32);
        assert_ne!(k1, k2);
    }

    #[test]
    fn legacy_session_key_is_identity() {
        let m = Method::Aes128Gcm;
        let id = identity_key(m, "x");
        assert_eq!(session_key(m, &id, b"salt"), id);
    }
}
