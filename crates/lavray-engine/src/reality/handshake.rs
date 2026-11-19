// SPDX-License-Identifier: GPL-3.0-only

//! Этапы TLS 1.3 handshake REALITY-клиента: драйвер handshake-фазы,
//! REALITY-верификация, Client Finished, разбор ServerHello/листа.

use crate::reality::{
    RealityError, kdf,
    record::{decrypt, read_record},
};
use tokio::net::TcpStream;

/// Драйвер handshake-фазы: читает зашифрованные записи, собирает
/// handshake-СООБЩЕНИЯ (склейка/разрезание по 4-байтовому заголовку),
/// кладёт их в транскрипт; возвращает DER листа и серверный seq.
pub(crate) async fn drive_handshake(
    tcp_r: &mut tokio::io::ReadHalf<TcpStream>,
    s_keys: &kdf::TrafficKeys,
    transcript: &mut Vec<Vec<u8>>,
) -> Result<(&'static [u8], u64), String> {
    let mut s_seq = 0u64;
    let mut stream: Vec<u8> = Vec::new();
    let mut consumed = 0usize;
    let mut leaf: Option<Vec<u8>> = None;
    loop {
        let (rec_type, ver, payload) = read_record(tcp_r).await.map_err(|e| e.0)?;
        if rec_type == 21 {
            return Err(format!("server alert: {:02x}{:02x}", ver[0], ver[1]));
        }
        if rec_type == 20 {
            // ChangeCipherSpec (middlebox-compat) — игнорируем
            continue;
        }
        if rec_type != 23 {
            return Err(format!("unexpected record type {rec_type}"));
        }

        let (_inner, content) = decrypt(s_keys, s_seq, rec_type, ver, &payload).map_err(|e| e.0)?;
        s_seq += 1;
        stream.extend_from_slice(&content);
        // парс полных handshake-сообщений из потока
        loop {
            if stream.len() - consumed < 4 {
                break;
            }
            let msg_len = usize::from(stream[consumed + 1] & 0x0F) << 16
                | usize::from(stream[consumed + 2]) << 8
                | usize::from(stream[consumed + 3]);
            let msg_total = 4 + msg_len;
            if stream.len() - consumed < msg_total {
                break;
            }
            let msg = stream[consumed..consumed + msg_total].to_vec();
            consumed += msg_total;

            match msg[0] {
                8 => {
                    // EncryptedExtensions — в транскрипт
                    transcript.push(msg);
                }
                11 => {
                    leaf = Some(
                        extract_leaf_der(&msg)
                            .ok_or_else(|| "bad certificate".to_string())?
                            .to_vec(),
                    );
                    transcript.push(msg);
                }
                24 => {
                    // NewSessionTicket — не в транскрипте рукопожатия
                }
                20 => {
                    // Finished: последний handshake — конец фазы
                    transcript.push(msg);
                    let leaf_ref = leaf
                        .as_ref()
                        .ok_or_else(|| "no leaf certificate".to_string())?;
                    let leaked: &'static [u8] = Box::leak(leaf_ref.clone().into_boxed_slice());
                    return Ok((leaked, s_seq));
                }
                _ => transcript.push(msg),
            }
        }
    }
}

// ---- вспомогательные ----

/// x25519 через x25519-dalek: приватный ключ живёт до конца handshake
/// ServerHello: извлечь server key_share x25519 (extension 0x0033, group 0x001D).
pub(crate) fn parse_server_hello_share(payload: &[u8]) -> Result<[u8; 32], RealityError> {
    if payload.len() < 4 {
        return Err(RealityError("server hello truncated".into()));
    }
    if payload[0] != 0x02 {
        return Err(RealityError(format!("not server hello: {}", payload[0])));
    }
    let body = &payload[4..];
    if body.len() < 35 {
        return Err(RealityError("server hello too short".into()));
    }
    let mut pos = 34; // body = сообщение БЕЗ handshake-заголовка: version(2)+random(32)
    let sid_len = usize::from(body[pos]);
    pos += 1 + sid_len;
    if pos + 3 > body.len() {
        return Err(RealityError("server hello: no cipher".into()));
    }
    pos += 2; // cipher suite
    pos += 1; // compression
    if pos + 2 > body.len() {
        return Err(RealityError("server hello: no extensions".into()));
    }
    let _ext_total = usize::from(body[pos]) << 8 | usize::from(body[pos + 1]);
    pos += 2;
    // перебор расширений: найти key_share (0x0033)
    while pos + 4 <= body.len() {
        let etype = usize::from(body[pos]) << 8 | usize::from(body[pos + 1]);
        let elen = usize::from(body[pos + 2]) << 8 | usize::from(body[pos + 3]);
        let ebody = body
            .get(pos + 4..pos + 4 + elen)
            .ok_or_else(|| RealityError("server hello: ext truncated".into()))?;
        if etype == 0x0033 {
            // key_share_list: client_share? server: [group(2), key(32)]
            // key_share data: RFC 8446 — server: group(2)+key(32) (без list_len);
            // openssl шлёт group(2)+key(32) напрямую, некоторые — с list_len(2).
            // openssl/Go сервер: group(2) + key_len(2) + key(32)
            if elen >= 36 && ebody[0] == 0x00 && ebody[1] == 0x1D {
                let mut out = [0u8; 32];
                out.copy_from_slice(&ebody[4..36]);
                return Ok(out);
            }
            // строгий RFC: group(2) + key(32) без key_len
            if elen >= 34 && ebody[0] == 0x00 && ebody[1] == 0x1D {
                let mut out = [0u8; 32];
                out.copy_from_slice(&ebody[2..34]);
                return Ok(out);
            }
        }
        pos += 4 + elen;
    }
    Err(RealityError("no x25519 key share".into()))
}

/// Из Certificate-сообщения взять DER листа (первая запись списка).
fn extract_leaf_der(certificate_msg: &[u8]) -> Option<&[u8]> {
    // handshake: type(11) len(3) body:
    //   certificate_request_context (1-byte len, обычно пустой)
    //   + certificate_list (3-byte len) + entry (3-byte len) + DER
    if certificate_msg.first() != Some(&11) || certificate_msg.len() < 8 {
        return None;
    }
    let body = &certificate_msg[4..];
    if body.is_empty() {
        return None;
    }
    let ctx_len = usize::from(body[0]);
    let mut pos = 1 + ctx_len;
    if pos + 3 > body.len() {
        return None;
    }
    pos += 3; // certificate_list length
    if pos + 3 > body.len() {
        return None;
    }
    let entry_len =
        usize::from(body[pos]) << 16 | usize::from(body[pos + 1]) << 8 | usize::from(body[pos + 2]);
    pos += 3;
    body.get(pos..pos.saturating_add(entry_len))
}
