// SPDX-License-Identifier: GPL-3.0-only

//! Ответ-заголовок VMess-сервера: [18Б AEAD(len=2)][2+16 AEAD(respBody)].

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::vmess::kdf::{kdf, salt, sha256_16};

pub(super) async fn send_response_header(
    stream: &mut TcpStream,
    req_key: &[u8; 16],
    req_nonce: &[u8; 16],
) -> std::io::Result<()> {
    let resp_key = sha256_16(req_key);
    let resp_nonce = sha256_16(req_nonce);
    let len_key = kdf(&resp_key, salt::RESP_LEN_KEY, &[]);
    let len_nonce = kdf(&resp_nonce, salt::RESP_LEN_NONCE, &[]);
    let hdr_key = kdf(&resp_key, salt::RESP_KEY, &[]);
    let hdr_nonce = kdf(&resp_nonce, salt::RESP_NONCE, &[]);

    let a1 = Aes128Gcm::new_from_slice(&len_key[..16]).expect("16");
    let a2 = Aes128Gcm::new_from_slice(&hdr_key[..16]).expect("16");
    let resp_body = [0u8, 1u8]; // responseHeader, option
    let sealed_len = a1
        .encrypt(
            GenericArray::from_slice(&len_nonce[..12]),
            2u16.to_be_bytes().as_slice(),
        )
        .expect("nonce уникален");
    let sealed_hdr = a2
        .encrypt(
            GenericArray::from_slice(&hdr_nonce[..12]),
            resp_body.as_slice(),
        )
        .expect("nonce уникален");
    stream.write_all(&sealed_len).await?;
    stream.write_all(&sealed_hdr).await?;
    Ok(())
}
