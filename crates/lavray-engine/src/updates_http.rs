// SPDX-License-Identifier: GPL-3.0-only

//! HTTP-слой updates: HTTPS GET до EOF (rustls + webpki-roots),
//! разбор ответа (статус/chunked). Паттерн lavray-dns doh_client.

use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// HTTPS GET до EOF (rustls + webpki-roots; паттерн lavray-dns).
pub(crate) async fn https_get(url: &str) -> io::Result<Vec<u8>> {
    let (host, path) = split_url(url)?;
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| io::Error::other("bad server name"))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect((host.as_str(), 443)).await?;
    let mut tls = connector.connect(server_name, stream).await?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: lavray-core\r\nAccept: application/vnd.github+json\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if std::time::Instant::now() > deadline {
            break;
        }
        let mut chunk = [0u8; 16384];
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => response.extend_from_slice(&chunk[..n]),
        }
    }
    Ok(response)
}

/// Разобрать URL https://host/path → (host, path).
fn split_url(url: &str) -> io::Result<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "только https"))?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    Ok((host.to_string(), format!("/{path}")))
}

/// Тело HTTP-ответа: статус 200 + Content-Length/chunked/до EOF.
pub(crate) fn http_body(response: &[u8]) -> io::Result<Vec<u8>> {
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no http header end"))?;
    let head = String::from_utf8_lossy(&response[..header_end]).into_owned();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;
    if status != 200 {
        return Err(io::Error::other(format!("http status {status}")));
    }
    let mut body = response[header_end + 4..].to_vec();
    if head.to_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body);
    }
    Ok(body)
}

/// Разобрать chunked-кодировку.
fn dechunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut rest: &[u8] = data;
    while let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") {
        let len_str = String::from_utf8_lossy(&rest[..line_end]).into_owned();
        let Ok(len) = usize::from_str_radix(len_str.trim(), 16) else {
            break;
        };
        rest = &rest[line_end + 2..];
        if len == 0 || rest.len() < len {
            break;
        }
        out.extend_from_slice(&rest[..len]);
        rest = &rest[len..];
        if rest.len() >= 2 {
            rest = &rest[2..];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_body_status_and_chunked() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(http_body(resp).expect("body"), b"hello");
        let resp404 = b"HTTP/1.1 404 NF\r\n\r\n";
        assert!(http_body(resp404).is_err());
    }
}
