// SPDX-License-Identifier: GPL-3.0-only

//! Разбор запроса VMess (тест-сервер): AuthID (AES-ECB + crc32),
//! len-AEAD → nonce8 → header-AEAD (fnv1a, адрес). AAD и KDF-пути —
//! СЫРОЙ AuthID с провода (до ECB-расшифровки).

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::addr::TargetAddr;
use crate::vmess::kdf::{aes_ecb_decrypt_block, fnv1a32, kdf, salt};
use crate::vmess::target::parse_addr;

/// Итог разбора: ключи тела (запрос) и цель.
pub(super) async fn parse_request(
    stream: &mut TcpStream,
    key: &[u8; 16],
) -> std::io::Result<([u8; 16], [u8; 16], TargetAddr)> {
    let mut auth = [0u8; 16];
    stream.read_exact(&mut auth).await?;
    let raw_auth = auth; // AAD — сырой AuthID с провода
    let enc: Vec<u8> = kdf(key, salt::AUTH_ID_ENC, &[]);
    let enc_key: [u8; 16] = enc[..16].try_into().expect("16");
    aes_ecb_decrypt_block(&enc_key, &mut auth);
    if crc32fast::hash(&auth[..12]).to_be_bytes() != auth[12..] {
        return Err(std::io::Error::other("vmess: authID crc не сошёлся"));
    }

    let mut sealed_len = [0u8; 18];
    stream.read_exact(&mut sealed_len).await?;
    let mut nonce8 = [0u8; 8];
    stream.read_exact(&mut nonce8).await?;

    let len_key = derive16(key, salt::HDR_LEN_KEY, &raw_auth, nonce8);
    let len_nonce = derive12(key, salt::HDR_LEN_NONCE, &raw_auth, nonce8);
    let aead = Aes128Gcm::new_from_slice(&len_key).expect("16");
    let pt = aead
        .decrypt(
            GenericArray::from_slice(&len_nonce),
            Payload {
                msg: &sealed_len,
                aad: &raw_auth,
            },
        )
        .map_err(|_| std::io::Error::other("vmess: len-AEAD не сошёлся"))?;
    let hdr_len = u16::from_be_bytes([pt[0], pt[1]]) as usize;

    let mut sealed_hdr = vec![0u8; hdr_len + 16];
    stream.read_exact(&mut sealed_hdr).await?;
    let hdr_key = derive16(key, salt::HDR_KEY, &raw_auth, nonce8);
    let hdr_nonce = derive12(key, salt::HDR_NONCE, &raw_auth, nonce8);
    let aead = Aes128Gcm::new_from_slice(&hdr_key).expect("16");
    let hdr = aead
        .decrypt(
            GenericArray::from_slice(&hdr_nonce),
            Payload {
                msg: &sealed_hdr,
                aad: &raw_auth,
            },
        )
        .map_err(|_| std::io::Error::other("vmess: header-AEAD не сошёлся"))?;
    if hdr.len() < 38 + 4 || hdr[0] != 1 {
        return Err(std::io::Error::other("vmess: версия/длина заголовка"));
    }
    let body = &hdr[..hdr.len() - 4];
    if fnv1a32(body).to_be_bytes() != hdr[hdr.len() - 4..] {
        return Err(std::io::Error::other("vmess: fnv заголовка не сошёлся"));
    }
    let req_nonce: [u8; 16] = hdr[1..17].try_into().expect("16");
    let req_key: [u8; 16] = hdr[17..33].try_into().expect("16");
    // [33]resp [34]opt [35]pad|sec [36]rsv [37]cmd [38..]addr
    if hdr[37] != 1 {
        return Err(std::io::Error::other("vmess: только TCP"));
    }
    let (target, _) = parse_addr(&hdr[38..])?;
    Ok((req_key, req_nonce, target))
}

fn derive16(key: &[u8; 16], s: &str, auth: &[u8; 16], nonce8: [u8; 8]) -> [u8; 16] {
    kdf(key, s, &[auth, &nonce8])[..16].try_into().expect("16")
}

fn derive12(key: &[u8; 16], s: &str, auth: &[u8; 16], nonce8: [u8; 8]) -> [u8; 12] {
    kdf(key, s, &[auth, &nonce8])[..12].try_into().expect("12")
}
