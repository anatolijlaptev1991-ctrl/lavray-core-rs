// SPDX-License-Identifier: GPL-3.0-only

//! WebSocket-клиент (RFC 6455, клиентская сторона): HTTP Upgrade поверх
//! TCP/TLS, затем бинарные фреймы. Используется как транспорт
//! vmess/vless/trojan (конфиг-поле network="ws"). Ping от сервера MVP
//! игнорирует (long-lived прокси-туннели его не шлют), Close — EOF.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ws::frame::WsReadHalf;
use crate::ws::write::WsWriteHalf;

/// Параметры ws-подключения.
#[derive(Debug, Clone)]
pub struct WsDial {
    /// Путь (с "/" впереди; пусто — "/").
    pub path: String,
    /// Заголовок Host (пусто — хост сервера).
    pub host: String,
}

/// Выполнить Upgrade-рукопожатие над TCP-потоком; возвращает фреймовые
/// половины (чтение серверных, запись маскированных).
pub async fn handshake(
    io: TcpStream,
    dial: &WsDial,
    fallback_host: &str,
) -> std::io::Result<(WsReadHalf, WsWriteHalf)> {
    let mut io = io;
    let path = if dial.path.is_empty() {
        "/"
    } else {
        &dial.path
    };
    let host = if dial.host.is_empty() {
        fallback_host
    } else {
        &dial.host
    };
    let mut key_raw = [0u8; 16];
    getrandom::fill(&mut key_raw).map_err(|e| std::io::Error::other(format!("ws key: {e}")))?;
    let key = b64(&key_raw);

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    io.write_all(req.as_bytes()).await?;

    // Читать заголовок ответа до \r\n\r\n.
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        let n = io.read(&mut b).await?;
        if n == 0 {
            return Err(std::io::Error::other("ws: обрыв при рукопожатии"));
        }
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 8 * 1024 {
            return Err(std::io::Error::other("ws: заголовок ответа >8 КиБ"));
        }
    }
    let text = String::from_utf8_lossy(&head);
    let status = text.lines().next().unwrap_or_default();
    if !status.contains(" 101 ") {
        return Err(std::io::Error::other(format!(
            "ws: не Switching Protocols: {status}"
        )));
    }
    // Проверка Sec-WebSocket-Accept опущена осознанно: туннель к своему
    // прокси-серверу, конфиденциальность даёт TLS; нестандартные серверы
    // (sing-box early-data) могут отдавать поле иначе.
    let (r, w) = io.into_split();
    Ok((WsReadHalf::new(r), WsWriteHalf::new(w, None)))
}

/// base64 (стандартный алфавит, без padding-зависимостей).
fn b64(raw: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(raw.len().div_ceil(3) * 4);
    for chunk in raw.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn b64_known_vectors() {
        assert_eq!(super::b64(&[]), "");
        assert_eq!(super::b64(b"f"), "Zg==");
        assert_eq!(super::b64(b"fo"), "Zm8=");
        assert_eq!(super::b64(b"foo"), "Zm9v");
        assert_eq!(super::b64(&[0xfb, 0xff]), "+/8=");
    }
}
