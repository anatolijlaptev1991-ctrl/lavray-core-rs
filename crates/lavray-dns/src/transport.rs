// SPDX-License-Identifier: GPL-3.0-only

//! DNS-транспорты: UDP (RFC 1035) и DoH (RFC 8484). Обмен с таймаутом;
//! сервер-адреса — «host:port» (UDP) и https-URL (DoH).

use crate::message::Message;
use crate::wire::parse;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Ошибка обмена.
#[derive(Debug)]
pub enum ExchangeError {
    /// Транспорт/таймаут.
    Io(String),
    /// Битый ответ.
    Parse(String),
}

impl std::fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "dns: exchange: {s}"),
            Self::Parse(s) => write!(f, "dns: {s}"),
        }
    }
}

impl std::error::Error for ExchangeError {}

/// UDP-обмен (порт transport/local): один запрос — один сокет.
///
/// # Errors
/// I/O / парс ответа.
pub async fn exchange_udp(
    server: &str,
    message: &Message,
    timeout: Duration,
) -> Result<Message, ExchangeError> {
    let wire = crate::wire::build(message);
    // бинд по семейству адреса сервера (os error 10014 при чужом семействе)
    let bind_addr = if server.starts_with('[') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| ExchangeError::Io(e.to_string()))?;
    socket
        .send_to(&wire, server)
        .await
        .map_err(|e| ExchangeError::Io(e.to_string()))?;
    let mut buf = vec![0u8; 64 * 1024];
    let recv = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .map_err(|_| ExchangeError::Io("timeout".into()))?
        .map_err(|e| ExchangeError::Io(e.to_string()))?;
    buf.truncate(recv.0);
    parse(&buf).map_err(|e| ExchangeError::Parse(e.to_string()))
}

/// DoH-обмен (RFC 8484 POST): URL `https://host[:port]/path`.
///
/// # Errors
/// I/O / TLS / HTTP-статус / парс.
pub async fn exchange_doh(
    url: &str,
    message: &Message,
    timeout: Duration,
) -> Result<Message, ExchangeError> {
    let (host, port, path) =
        parse_doh_url(url).ok_or_else(|| ExchangeError::Parse("bad doh url".into()))?;
    let wire = crate::wire::build(message);
    Box::pin(crate::doh_client::exchange_doh(
        &host, port, &path, &wire, timeout,
    ))
    .await
    .map_err(ExchangeError::Io)
}

fn parse_doh_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/dns-query".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 443),
    };
    Some((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_url_parse() {
        assert_eq!(
            parse_doh_url("https://dns.google/dns-query"),
            Some(("dns.google".into(), 443, "/dns-query".into()))
        );
        assert_eq!(
            parse_doh_url("https://1.1.1.1"),
            Some(("1.1.1.1".into(), 443, "/dns-query".into()))
        );
        assert_eq!(parse_doh_url("http://x/"), None);
    }
}
