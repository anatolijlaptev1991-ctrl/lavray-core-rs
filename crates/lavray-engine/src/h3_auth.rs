// SPDX-License-Identifier: GPL-3.0-only

//! HTTP/3-минимум для hysteria2 auth: HEADERS-кадр (QPACK literal
//! без сжатия) + чтение ответа со статусом.

use crate::hy2::{
    AUTH_HEADER, AUTH_PADDING, CC_RX_HEADER, PADDING_HEADER, URL_PATH, read_varint, varint_len,
};
use crate::hy2_config::write_varint;

/// HTTP/3 auth-запрос: HEADERS-кадр с псевдо-заголовками + DATA.
/// Минимальная реализация QPACK без сжатия (literal-without-name-ref).
pub(crate) async fn send_h3_auth(
    send: &mut quinn::SendStream,
    password: &str,
    rx_bps: u64,
) -> Result<(), String> {
    // QPACK header block: literal header field never indexed (0x10/0x00)
    let mut headers = Vec::new();
    push_h3_header(&mut headers, b":method", b"POST");
    push_h3_header(&mut headers, b":scheme", b"https");
    push_h3_header(&mut headers, b":authority", b"hysteria");
    push_h3_header(&mut headers, b":path", URL_PATH.as_bytes());
    push_h3_header(&mut headers, AUTH_HEADER.as_bytes(), password.as_bytes());
    push_h3_header(
        &mut headers,
        CC_RX_HEADER.as_bytes(),
        rx_bps.to_string().as_bytes(),
    );
    push_h3_header(
        &mut headers,
        PADDING_HEADER.as_bytes(),
        AUTH_PADDING.as_bytes(),
    );

    // HTTP/3 frames: DATA(0x0) и HEADERS(0x1) с varint length
    let mut out = Vec::new();
    // HEADERS frame
    write_varint(&mut out, 0x1);
    write_varint(&mut out, headers.len() as u64);
    out.extend_from_slice(&headers);
    // DATA frame (пустое тело POST)
    write_varint(&mut out, 0x0);
    write_varint(&mut out, 0);
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
    // QPACK literal: ищем байты «233» (ASCII) — статус-строка
    let text = String::from_utf8_lossy(&headers).into_owned();
    Ok(text.contains("233"))
}

/// Записать H3 literal header (name и value с префиксом длины).
fn push_h3_header(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    // literal header field never indexed — new name (0x00), huffman off
    out.push(0x00);
    write_varint(out, name.len() as u64);
    out.extend_from_slice(name);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}
