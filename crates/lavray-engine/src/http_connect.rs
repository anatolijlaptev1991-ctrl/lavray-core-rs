// SPDX-License-Identifier: GPL-3.0-only

//! HTTP CONNECT-инбаунд (RFC 7231): единственный метод — CONNECT
//! authority-form; остальное — 405. Голова читается чанками до пустой
//! строки; байты ЗА разделителем возвращаются вызывающему (их отправляет
//! relay первым — часть TLS ClientHello клиента могла уже прийти).

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::addr::TargetAddr;

/// Лимит головы запроса (браузеры укладываются в 8 КиБ).
const MAX_HEAD: usize = 8 * 1024;
/// Размер чанка чтения головы.
const CHUNK: usize = 512;

/// Прочитать запрос CONNECT.
/// `Ok(None)` — не-CONNECT или невалидный authority (вызывающий — 405).
/// `Ok(Some((addr, tail)))` — цель и уже прочитанные байты данных клиента.
/// `Err` — обрыв/переполнение головы.
pub async fn read_connect<S>(s: &mut S) -> std::io::Result<Option<(TargetAddr, Vec<u8>)>>
where
    S: AsyncReadExt + Unpin,
{
    let mut head: Vec<u8> = Vec::with_capacity(CHUNK);
    let mut chunk = [0u8; CHUNK];
    let split = loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(eof());
        }
        let start = head.len();
        head.extend_from_slice(&chunk[..n]);
        // Перекрытие 3 байта: разделитель мог начаться в прошлом чанке.
        let from = start.saturating_sub(3);
        if let Some(pos) = find_split(&head[from..]).map(|p| p + from) {
            break pos;
        }
        if head.len() > MAX_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP: голова больше 8 КиБ",
            ));
        }
    };
    let sep_len = split_len(&head[split..]);
    let tail = head.split_off(split + sep_len);
    let first = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let first = String::from_utf8_lossy(first);
    let first = first.trim_end_matches('\r');
    let mut parts = first.split_whitespace();
    let (method, authority) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Ok(None);
    }
    Ok(TargetAddr::parse(authority).map(|a| (a, tail)))
}

/// Позиция разделителя (\r\n\r\n или \n\n) в слайсе.
fn find_split(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    (0..buf.len() - 1).find(|&i| {
        (buf[i] == b'\n' && buf[i + 1] == b'\n')
            || (buf[i] == b'\r'
                && buf.get(i + 1) == Some(&b'\n')
                && buf.get(i + 2) == Some(&b'\r')
                && buf.get(i + 3) == Some(&b'\n'))
    })
}

/// Длина разделителя, начинающегося в split (по первому байту).
fn split_len(head: &[u8]) -> usize {
    if head.first() == Some(&b'\r') { 4 } else { 2 }
}

fn eof() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "HTTP: обрыв головы")
}

/// Ответы.
pub async fn reply_ok<S>(s: &mut S) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
}

pub async fn reply_405<S>(s: &mut S) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    s.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        .await
}

pub async fn reply_502<S>(s: &mut S) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    s.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        .await
}
