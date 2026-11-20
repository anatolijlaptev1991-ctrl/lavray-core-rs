// SPDX-License-Identifier: GPL-3.0-only

//! HTTP/3-минимум для hysteria2 auth: HEADERS-кадр (QPACK literal
//! без сжатия) + чтение ответа со статусом.

use crate::hy2::{AUTH_PADDING, URL_PATH, read_varint, varint_len};
use crate::hy2_config::write_varint;

/// HTTP/3 auth-запрос: HEADERS-кадр с псевдо-заголовками + DATA.
/// Минимальная реализация QPACK без сжатия (literal-without-name-ref).
pub async fn send_h3_auth(
    send: &mut quinn::SendStream,
    password: &str,
    rx_bps: u64,
) -> Result<(), String> {
    // QPACK header block. Имена заголовков — строго lowercase (RFC 9114
    // §4.2: HTTP/3-парсер sing-box отклоняет не-lowercase с H3 MessageError).
    // Go-клиент нормализует имена через net/http — здесь константы в hex.
    let mut headers = Vec::new();
    push_h3_header(&mut headers, b":method", b"POST");
    push_h3_header(&mut headers, b":scheme", b"https");
    push_h3_header(&mut headers, b":authority", b"hysteria");
    push_h3_header(&mut headers, b":path", URL_PATH.as_bytes());
    push_h3_header(&mut headers, b"hysteria-auth", password.as_bytes());
    push_h3_header(
        &mut headers,
        b"hysteria-cc-rx",
        rx_bps.to_string().as_bytes(),
    );
    push_h3_header(&mut headers, b"hysteria-padding", AUTH_PADDING.as_bytes());

    // QPACK header block prefix (RFC 9204 §4.3): Required Insert Count
    // (динамическая таблица не используется → 0) и Delta Base (0).
    let mut block = Vec::with_capacity(headers.len() + 2);
    write_varint(&mut block, 0);
    write_varint(&mut block, 0);
    block.extend_from_slice(&headers);

    // HTTP/3 HEADERS-кадр; тело POST пустое — DATA-кадр не шлём
    // (RFC 9114: запрос без тела = только HEADERS).
    let mut out = Vec::new();
    write_varint(&mut out, 0x1);
    write_varint(&mut out, block.len() as u64);
    out.extend_from_slice(&block);
    send.write_all(&out).await.map_err(|e| e.to_string())
}

/// Прочитать HTTP/3-ответ: HEADERS-кадр со статусом (233 = auth ok).
pub(crate) async fn read_h3_auth_response(recv: &mut quinn::RecvStream) -> Result<bool, String> {
    // кадр: type (varint) + length (varint) + payload
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|e| e.to_string())?;
    let ftype_len = varint_len(first[0]);
    let mut type_buf = vec![first[0]];
    if ftype_len > 1 {
        let mut rest = vec![0u8; ftype_len - 1];
        recv.read_exact(&mut rest)
            .await
            .map_err(|e| e.to_string())?;
        type_buf.extend_from_slice(&rest);
    }
    let (frame_type, _) = read_varint(&type_buf).map_err(|e| e.0)?;
    if frame_type != 0x1 {
        return Ok(false); // не HEADERS
    }
    // length varint
    let mut len_buf = vec![0u8; 1];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| e.to_string())?;
    let len_total = varint_len(len_buf[0]);
    let mut rest = vec![0u8; len_total - 1];
    recv.read_exact(&mut rest)
        .await
        .map_err(|e| e.to_string())?;
    len_buf.extend_from_slice(&rest);
    let (frame_len, used) = read_varint(&len_buf).map_err(|e| e.0)?;
    let _ = used;

    #[allow(clippy::cast_possible_truncation)] // frame_len из varint, ограничен 2048 в протоколе
    let mut headers = vec![0u8; frame_len as usize];
    recv.read_exact(&mut headers)
        .await
        .map_err(|e| e.to_string())?;
    // Статус ищем в QPACK-блоке сервера: значения Go-энкодер шлёт
    // HPACK-huffman'ом (`:status 233` → name-ref static idx 24 +
    // huffman [13 2c ff]); ASCII-«233» — fallback для без-huffman.
    Ok(contains_ascii_or_huffman_233(&headers))
}

/// HPACK-huffman-код «233» (RFC 7541 App. B, канонические коды) —
/// ровно 3 байта, подтверждено декодером python-hpack против сервера.
const HUFFMAN_233_BYTES: [u8; 3] = [0x13, 0x2c, 0xff];

/// Ищет «233» в QPACK-блоке: как ASCII-байты или как huffman-паттерн.
fn contains_ascii_or_huffman_233(payload: &[u8]) -> bool {
    payload.windows(3).any(|w| w == b"233") || payload.windows(3).any(|w| w == HUFFMAN_233_BYTES)
}

/// Записать H3 literal header (qpack-go-формат, RFC 9204): инструкция
/// `001` + huffman-бит 0x08 (H=0) + HPACK-varint с 3-битным префиксом
/// длины имени; затем 7-битный префикс длины значения.
pub fn push_h3_header(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    let n = name.len();
    let fits_prefix = u8::try_from(n).is_ok_and(|short| short < 7);
    if fits_prefix {
        #[allow(clippy::cast_possible_truncation)] // n < 7
        out.push(0x20 | n as u8);
        out.extend_from_slice(name);
        push_qvalue_len(out, value);
        return;
    }
    out.push(0x27); // 0x20 | префикс 7 → продолжение varint
    write_varint(out, u64::try_from(n - 7).unwrap_or(0));
    out.extend_from_slice(name);
    push_qvalue_len(out, value);
}

/// Длина значения: HPACK-varint с 7-битным префиксом (H=0).
fn push_qvalue_len(out: &mut Vec<u8>, value: &[u8]) {
    let v = value.len();
    let fits_prefix = u8::try_from(v).is_ok_and(|short| short < 127);
    if fits_prefix {
        #[allow(clippy::cast_possible_truncation)] // v < 127
        out.push(v as u8);
        out.extend_from_slice(value);
        return;
    }
    out.push(0x7F);
    write_varint(out, u64::try_from(v - 127).unwrap_or(0));
    out.extend_from_slice(value);
}
