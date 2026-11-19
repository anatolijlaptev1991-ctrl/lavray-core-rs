// SPDX-License-Identifier: GPL-3.0-only

//! VMess-клиент (AEAD, alterId=0; порт sing-vmess client.go): TCP →
//! [AuthID|len-AEAD|nonce8|header-AEAD] → ответ-заголовок сервера →
//! AEAD-блоки тела (ключи reqKey/SHA256(reqKey)).

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::addr::TargetAddr;
use crate::relay::{UpRead, UpWrite};
use crate::vmess::body::BodyReader;
use crate::vmess::header::{Security, build_request};
use crate::vmess::kdf::{kdf, salt, sha256_16};
use crate::vmess::write::BodyWriter;

/// Параметры исходящего VMess-туннеля.
#[derive(Debug, Clone)]
pub struct VmessOutbound {
    /// Адрес сервера.
    pub server: TargetAddr,
    /// UUID пользователя (строка).
    pub uuid: String,
    /// Шифр тела.
    pub security: Security,
}

/// UUID-строка → 16 байт (uuid-крейт покрывает все варианты записи).
#[must_use]
pub fn uuid_bytes(s: &str) -> Option<[u8; 16]> {
    let u = uuid::Uuid::parse_str(s).ok()?;
    Some(*u.as_bytes())
}

/// Установить туннель: возвращает половины тела (запись/чтение).
pub async fn connect(o: &VmessOutbound, target: &TargetAddr) -> std::io::Result<(UpRead, UpWrite)> {
    let uid =
        uuid_bytes(&o.uuid).ok_or_else(|| std::io::Error::other("vmess: некорректный UUID"))?;
    let (request, req_key, req_nonce) = build_request(&uid, o.security, target, now_unix());
    let mut stream = TcpStream::connect((o.server.host_string().as_str(), o.server.port())).await?;
    let _ = stream.set_nodelay(true);
    stream.write_all(&request).await?;

    // Ответ-заголовок: [18Б AEAD(len)][len+16 AEAD(respBody)].
    let resp_key = sha256_16(&req_key);
    let resp_nonce = sha256_16(&req_nonce);
    let len_key = kdf(&resp_key, salt::RESP_LEN_KEY, &[]);
    let len_nonce: [u8; 12] = kdf(&resp_nonce, salt::RESP_LEN_NONCE, &[])[..12]
        .try_into()
        .expect("12");
    let mut sealed_len = [0u8; 18];
    stream.read_exact(&mut sealed_len).await?;
    let len_aead = Aes128Gcm::new_from_slice(&len_key[..16]).expect("16 байт");
    let pt = len_aead
        .decrypt(g12(&len_nonce), sealed_len.as_ref())
        .map_err(|_| std::io::Error::other("vmess: ответ-заголовок (len) не сошёлся"))?;
    let resp_len = u16::from_be_bytes([pt[0], pt[1]]) as usize;
    let hdr_key = kdf(&resp_key, salt::RESP_KEY, &[]);
    let hdr_nonce: [u8; 12] = kdf(&resp_nonce, salt::RESP_NONCE, &[])[..12]
        .try_into()
        .expect("12");
    let mut sealed_hdr = vec![0u8; resp_len + 16];
    stream.read_exact(&mut sealed_hdr).await?;
    let hdr_aead = Aes128Gcm::new_from_slice(&hdr_key[..16]).expect("16 байт");
    hdr_aead
        .decrypt(
            g12(&hdr_nonce),
            Payload {
                msg: &sealed_hdr,
                aad: &[],
            },
        )
        .map_err(|_| std::io::Error::other("vmess: ответ-заголовок не сошёлся"))?;

    // Тело: запись — reqKey/reqNonce, чтение — respKey/respNonce.
    let (r, w) = stream.into_split();
    let wr = BodyWriter::new(w, o.security, &req_key, &req_nonce, None);
    let rd = BodyReader::new(r, o.security, &resp_key, &resp_nonce);
    Ok((Box::pin(rd), Box::pin(wr)))
}

/// [u8;12] → нонс AES-GCM.
fn g12(
    b: &[u8; 12],
) -> &aes_gcm::aead::generic_array::GenericArray<u8, aes_gcm::aead::consts::U12> {
    aes_gcm::aead::generic_array::GenericArray::from_slice(b)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
