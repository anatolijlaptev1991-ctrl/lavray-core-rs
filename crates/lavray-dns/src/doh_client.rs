// SPDX-License-Identifier: GPL-3.0-only

//! Минимальный DoH-клиент: rustls + HTTP/1.1 POST, one-shot соединение
//! (без пула — запрос в секунду не требует). webpki-roots как якоря.

use crate::message::Message;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Выполнить DoH POST и вернуть тело ответа.
///
/// # Errors
/// DNS/TCP/TLS/HTTP-ошибки (строки — из транспорте).
pub async fn exchange_doh(
    host: &str,
    port: u16,
    path: &str,
    wire: &[u8],
    timeout: Duration,
) -> Result<Message, String> {
    let fut = Box::pin(exchange_inner(host, port, path, wire));
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| "timeout".to_string())?
}

async fn exchange_inner(host: &str, port: u16, path: &str, wire: &[u8]) -> Result<Message, String> {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "bad server name".to_string())?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("tls: {e}"))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        wire.len()
    );
    tls.write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    tls.write_all(wire)
        .await
        .map_err(|e| format!("write: {e}"))?;

    // серверы часто рвут соединение без close_notify — читаем до EOF/ошибки
    let mut response = Vec::new();
    loop {
        let mut chunk = [0u8; 16384];
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => response.extend_from_slice(&chunk[..n]),
        }
    }

    // Разбор HTTP/1.1: статус + заголовки + тело (Content-Length или chunked).
    let header_end =
        find_subsequence(&response, b"\r\n\r\n").ok_or_else(|| "no http header end".to_string())?;
    let head = String::from_utf8_lossy(&response[..header_end]).into_owned();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| "bad status line".to_string())?;
    if status != 200 {
        return Err(format!("http status {status}"));
    }
    let lower = head.to_lowercase();
    let body = response[header_end + 4..].to_vec();
    let body = if lower.contains("transfer-encoding: chunked") {
        dechunk(&body).ok_or_else(|| "bad chunked body".to_string())?
    } else {
        body
    };
    crate::wire::parse(&body).map_err(|e| e.to_string())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn dechunk(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = data;
    loop {
        let line_end = find_subsequence(rest, b"\r\n")?;
        let size_str = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size = usize::from_str_radix(size_str.trim().split(';').next()?, 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if rest.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunk_round_trip() {
        let chunked = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(chunked), Some(b"Wikipedia".to_vec()));
    }

    #[test]
    fn find_subseq() {
        assert_eq!(find_subsequence(b"abc\r\n\r\nx", b"\r\n\r\n"), Some(3));
    }
}
