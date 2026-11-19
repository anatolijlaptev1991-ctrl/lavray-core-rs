// SPDX-License-Identifier: GPL-3.0-only

//! Record-слой TLS 1.3: чтение/запись записей (5-байтовый заголовок),
//! расшифровка AES-128-GCM с нонсом от sequence number, снятие
//! внутреннего content-type (tls13 inner: content+type+padding).

use crate::reality::kdf::TrafficKeys;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const HEADER_LEN: usize = 5;
const MAX_RECORD: usize = 16_777 + 5;

/// Ошибка record-слоя.
#[derive(Debug)]
pub struct RecordError(pub String);

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tls record: {}", self.0)
    }
}

/// Прочитать заголовок + payload записи (без расшифровки).
pub async fn read_record<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<(u8, [u8; 2], Vec<u8>), RecordError> {
    let mut hdr = [0u8; HEADER_LEN];
    r.read_exact(&mut hdr)
        .await
        .map_err(|e| RecordError(format!("read header: {e}")))?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > MAX_RECORD {
        return Err(RecordError(format!("record too large {len}")));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)
        .await
        .map_err(|e| RecordError(format!("read payload: {e}")))?;
    Ok((hdr[0], [hdr[1], hdr[2]], payload))
}

/// Расшифровать payload записи: nonce = iv XOR seq, AAD = заголовок.
/// Возвращает (content_type, plaintext) — последний ненулевой байт.
///
/// # Errors
/// Неверный GCM-тег.
pub fn decrypt(
    keys: &TrafficKeys,
    seq: u64,
    rec_type: u8,
    version: [u8; 2],
    payload: &[u8],
) -> Result<(u8, Vec<u8>), RecordError> {
    let cipher = Aes128Gcm::new((&keys.key).into());
    let nonce = keys.nonce_for(seq);
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.push(rec_type);
    header.extend_from_slice(&version);
    header.extend_from_slice(&(u16::try_from(payload.len()).unwrap_or(u16::MAX)).to_be_bytes());
    let plain = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: payload,
                aad: &header,
            },
        )
        .map_err(|_| RecordError("decryption failed".into()))?;
    // inner content: ... + type byte (+ zero padding)
    let mut end = plain.len();
    while end > 0 && plain[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(RecordError("empty inner content".into()));
    }
    let content_type = plain[end - 1];
    Ok((content_type, plain[..end - 1].to_vec()))
}

/// Зашифровать и вернуть payload записи (заголовок собирает отправитель).
pub fn encrypt(
    keys: &TrafficKeys,
    seq: u64,
    content_type: u8,
    version: [u8; 2],
    content: &[u8],
) -> Vec<u8> {
    let cipher = Aes128Gcm::new((&keys.key).into());
    let nonce = keys.nonce_for(seq);
    let mut inner = Vec::with_capacity(content.len() + 1);
    inner.extend_from_slice(content);
    inner.push(content_type);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.push(0x17); // application_data (зашифрованные записи всегда 23)
    header.extend_from_slice(&version);
    header.extend_from_slice(&(u16::try_from(inner.len() + 16).unwrap_or(u16::MAX)).to_be_bytes());
    let sealed = cipher.encrypt(
        (&nonce).into(),
        Payload {
            msg: &inner,
            aad: &header,
        },
    );
    sealed.expect("aes-gcm seal")
}

/// Записать зашифрованную запись.
pub async fn write_encrypted<W: AsyncWrite + Unpin>(
    w: &mut W,
    keys: &TrafficKeys,
    seq: u64,
    content_type: u8,
    content: &[u8],
) -> Result<(), RecordError> {
    let payload = encrypt(keys, seq, content_type, [0x03, 0x03], content);
    let mut out = Vec::with_capacity(payload.len() + HEADER_LEN);
    out.push(0x17);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&(u16::try_from(payload.len()).unwrap_or(u16::MAX)).to_be_bytes());
    out.extend_from_slice(&payload);
    w.write_all(&out)
        .await
        .map_err(|e| RecordError(format!("write: {e}")))?;
    w.flush()
        .await
        .map_err(|e| RecordError(format!("flush: {e}")))?;
    Ok(())
}

/// Записать открытую запись (ServerHello-этап).
pub async fn write_plain<W: AsyncWrite + Unpin>(
    w: &mut W,
    rec_type: u8,
    payload: &[u8],
) -> Result<(), RecordError> {
    let mut out = Vec::with_capacity(payload.len() + HEADER_LEN);
    out.push(rec_type);
    out.extend_from_slice(&[0x03, 0x01]); // legacy 0x0301 у ClientHello-записи
    out.extend_from_slice(&(u16::try_from(payload.len()).unwrap_or(u16::MAX)).to_be_bytes());
    out.extend_from_slice(payload);
    w.write_all(&out)
        .await
        .map_err(|e| RecordError(format!("write: {e}")))?;
    w.flush()
        .await
        .map_err(|e| RecordError(format!("flush: {e}")))?;
    Ok(())
}
