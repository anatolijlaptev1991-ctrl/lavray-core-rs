// SPDX-License-Identifier: GPL-3.0-only

//! Заголовок запроса VMess AEAD (порт sing-vmess client.go): AuthID
//! (AES-ECB), AEAD-инкапсуляция длины и тела заголовка, кодирование
//! headerBody (ver|nonce|key|опции|команда|адрес — ПОРТ ПЕРЕД адресом).

use aes_gcm::Aes128Gcm as Aes128GcmG;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};

use crate::addr::TargetAddr;
use crate::vmess::kdf::{aes_ecb_encrypt_block, fnv1a32, kdf, salt, user_key};

/// Security-типы тела (protocol.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Aes128Gcm,
    Chacha20Poly1305,
}

impl Security {
    /// Код в headerBody.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Aes128Gcm => 3,
            Self::Chacha20Poly1305 => 4,
        }
    }
}

/// Собрать запрос: [AuthID16][len-AEAD18][nonce8][headerBody-AEAD].
/// Возвращает (пишемое, requestKey16, requestNonce16 — для тела).
#[must_use]
pub fn build_request(
    uuid_bytes: &[u8; 16],
    security: Security,
    target: &TargetAddr,
    unix: u64,
) -> (Vec<u8>, [u8; 16], [u8; 16]) {
    let key = user_key(uuid_bytes);

    // AuthID: [unix_be64 | rand4 | crc32_be32(первые12)] → AES-ECB.
    let mut auth_plain = [0u8; 16];
    auth_plain[..8].copy_from_slice(&unix.to_be_bytes());
    getrandom::fill(&mut auth_plain[8..12]).expect("соль ОС");
    let crc = crc32fast::hash(&auth_plain[..12]);
    auth_plain[12..].copy_from_slice(&crc.to_be_bytes());
    let mut auth_id = auth_plain;
    let enc = kdf(&key, salt::AUTH_ID_ENC, &[]);
    let enc_key: [u8; 16] = enc[..16].try_into().expect("16");
    aes_ecb_encrypt_block(&enc_key, &mut auth_id);

    // headerBody (encodeHeader, paddingLen=0, option=1 chunk-stream).
    let mut nonce = [0u8; 16];
    let mut req_key = [0u8; 16];
    getrandom::fill(&mut nonce).expect("соль ОС");
    getrandom::fill(&mut req_key).expect("соль ОС");
    let mut body = Vec::with_capacity(64);
    body.push(1); // version
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&req_key);
    body.push(0); // responseAuth (рандом не обязателен: сервер не сверяет)
    body.push(1); // option: chunk-stream
    body.push(security.code()); // paddingLen(0)<<4 | security
    body.push(0); // reserved
    body.push(1); // command TCP
    push_addr(&mut body, target);
    let hash = fnv1a32(&body).to_be_bytes();
    body.extend_from_slice(&hash);

    // AEAD: длина и тело, aad = authId, path = [authId, nonce8].
    let mut nonce8 = [0u8; 8];
    getrandom::fill(&mut nonce8).expect("соль ОС");
    let len_key: [u8; 16] = kdf(&key, salt::HDR_LEN_KEY, &[&auth_id, &nonce8])[..16]
        .try_into()
        .expect("16");
    let len_nonce: [u8; 12] = kdf(&key, salt::HDR_LEN_NONCE, &[&auth_id, &nonce8])[..12]
        .try_into()
        .expect("12");
    let hdr_key: [u8; 16] = kdf(&key, salt::HDR_KEY, &[&auth_id, &nonce8])[..16]
        .try_into()
        .expect("16");
    let hdr_nonce: [u8; 12] = kdf(&key, salt::HDR_NONCE, &[&auth_id, &nonce8])[..12]
        .try_into()
        .expect("12");

    let len_pt = u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes();
    let sealed_len = seal(&len_key, &len_nonce, &auth_id, &len_pt);
    let sealed_hdr = seal(&hdr_key, &hdr_nonce, &auth_id, &body);

    let mut out = Vec::with_capacity(16 + sealed_len.len() + 8 + sealed_hdr.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&sealed_len);
    out.extend_from_slice(&nonce8);
    out.extend_from_slice(&sealed_hdr);
    (out, req_key, nonce)
}

/// AES-128-GCM Seal с AAD (заголовки VMess).
fn seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let cipher = Aes128GcmG::new_from_slice(key).expect("16 байт");
    cipher
        .encrypt(GenericArray::from_slice(nonce), Payload { msg: pt, aad })
        .expect("nonce уникален в рамках ключа")
}

/// Адрес: ПОРТ ПЕРЕД адресом (AddressSerializer PortThenAddress);
/// ATYP: 0x01 IPv4, 0x02 FQDN, 0x03 IPv6.
fn push_addr(body: &mut Vec<u8>, t: &TargetAddr) {
    match t {
        TargetAddr::Domain(d, p) => {
            body.extend_from_slice(&p.to_be_bytes());
            body.push(0x02);
            body.push(u8::try_from(d.len()).unwrap_or(255));
            body.extend_from_slice(d.as_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V4(v), p) => {
            body.extend_from_slice(&p.to_be_bytes());
            body.push(0x01);
            body.extend_from_slice(&v.octets());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(v), p) => {
            body.extend_from_slice(&p.to_be_bytes());
            body.push(0x03);
            body.extend_from_slice(&v.octets());
        }
    }
}
