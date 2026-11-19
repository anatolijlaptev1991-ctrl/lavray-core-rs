// SPDX-License-Identifier: GPL-3.0-only

//! TLS 1.3 key schedule (RFC 8448 §7.1, HKDF-SHA256): Expand-Label,
//! traffic secrets handshake-/application-фаз и их ключи AES-128-GCM.

use hkdf::Hkdf;
use hmac::Mac;
use sha2::Digest;
use sha2::Sha256;

/// HKDF-Extract (RFC 5869): HMAC-SHA256(salt, ikm).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(salt).expect("any salt len");
    mac.update(ikm);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

const LABEL_PREFIX: &[u8] = b"tls13 ";

fn expand_label(prk: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + LABEL_PREFIX.len() + label.len() + 1 + context.len());
    info.extend_from_slice(&(u16::try_from(len).unwrap_or(u16::MAX)).to_be_bytes());
    let full_label_len = LABEL_PREFIX.len() + label.len();
    info.push(u8::try_from(full_label_len).unwrap_or(u8::MAX));
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label.as_bytes());
    info.push(u8::try_from(context.len()).unwrap_or(u8::MAX));
    info.extend_from_slice(context);
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("prk len 32");
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).expect("expand len <= 255");
    out
}

pub fn transcript_hash(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Рабочие ключи одного направления (AES-128-GCM + 12-байтовый IV).
#[derive(Debug, Clone)]
pub struct TrafficKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
}

impl TrafficKeys {
    /// Из traffic secret.
    #[must_use]
    pub fn from_secret(secret: &[u8]) -> Self {
        let key_v = expand_label(secret, "key", &[], 16);
        let iv_v = expand_label(secret, "iv", &[], 12);
        let mut key = [0u8; 16];
        key.copy_from_slice(&key_v);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_v);
        Self { key, iv }
    }

    /// Нонс записи: IV XOR BE64(seq) справа (RFC 8439 §3.3).
    #[must_use]
    pub fn nonce_for(&self, seq: u64) -> [u8; 12] {
        let seq_bytes = seq.to_be_bytes();
        let mut nonce = self.iv;
        for (i, b) in seq_bytes.iter().enumerate() {
            nonce[4 + i] ^= *b;
        }
        nonce
    }
}

/// Секреты TLS 1.3: handshake- и application-фазы.
#[derive(Debug, Clone)]
pub struct Schedule {
    pub client_hs: Vec<u8>,
    pub server_hs: Vec<u8>,
    pub client_ap: Vec<u8>,
    pub server_ap: Vec<u8>,
    master: Vec<u8>,
}

impl Schedule {
    /// Из ECDHE-общего секрета и ГОТОВОГО хэша транскрипта
    /// (SHA-256 ClientHello‖ServerHello; RFC 8448 §7.1).
    #[must_use]
    pub fn new(ecdhe_shared: &[u8], transcript_hash: &[u8; 32]) -> Self {
        // Extract-цепочка (RFC 8448 §7.1): «derived» использует контекст
        // Hash("") = e3b0c442… (Derive-Secret с пустым списком сообщений).
        let empty_hash = sha2::Sha256::digest([]);
        let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
        let derived = expand_label(&early, "derived", &empty_hash, 32);
        let handshake = hkdf_extract(&derived, ecdhe_shared);
        let derived2 = expand_label(&handshake, "derived", &empty_hash, 32);
        let master_prk = hkdf_extract(&derived2, &[0u8; 32]);

        let th = *transcript_hash;
        // hs traffic — из HANDSHAKE secret (RFC 8446 §7.1); ap — из master
        Self {
            client_hs: expand_label(&handshake, "c hs traffic", &th, 32),
            server_hs: expand_label(&handshake, "s hs traffic", &th, 32),
            client_ap: Vec::new(),
            server_ap: Vec::new(),
            master: master_prk.to_vec(),
        }
    }

    /// Application-секреты по ГОТОВОМУ hash транскрипта (CH…SF‖CF;
    /// RFC 8448 §3: hash = 9608102a…).
    pub fn derive_app(&mut self, transcript_hash: &[u8; 32]) {
        self.client_ap = expand_label(&self.master, "c ap traffic", transcript_hash, 32);
        self.server_ap = expand_label(&self.master, "s ap traffic", transcript_hash, 32);
    }

    /// Ключи клиента handshake-фазы.
    #[must_use]
    pub fn client_hs_keys(&self) -> TrafficKeys {
        TrafficKeys::from_secret(&self.client_hs)
    }
    /// Ключи сервера handshake-фазы.
    #[must_use]
    pub fn server_hs_keys(&self) -> TrafficKeys {
        TrafficKeys::from_secret(&self.server_hs)
    }
    /// Ключи клиента application-фазы.
    #[must_use]
    pub fn client_ap_keys(&self) -> TrafficKeys {
        TrafficKeys::from_secret(&self.client_ap)
    }
    /// Ключи сервера application-фазы.
    #[must_use]
    pub fn server_ap_keys(&self) -> TrafficKeys {
        TrafficKeys::from_secret(&self.server_ap)
    }
}

/// finished_key = Expand-Label(secret, "finished", "", 32)
/// (RFC 8446 §4.4.4).
#[must_use]
pub fn finished_key(secret: &[u8]) -> [u8; 32] {
    let v = expand_label(secret, "finished", &[], 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}
