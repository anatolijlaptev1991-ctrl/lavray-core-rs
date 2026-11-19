// SPDX-License-Identifier: GPL-3.0-only

//! DNS over TLS (RFC 7858): TLS host:853, сообщения с 2-байтовым
//! BE length-prefix; один запрос — одно соединение.

use crate::message::Message;
use crate::wire::parse;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// DoT-обмен: `host:853` (порт в адресе), TLS-верификация webpki-roots.
///
/// # Errors
/// TCP/TLS/таймаут/парс.
pub async fn exchange_dot(
    server: &str,
    message: &Message,
    timeout: Duration,
) -> Result<Message, String> {
    let fut = exchange_inner(server, message);
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| "timeout".to_string())?
}

async fn exchange_inner(server: &str, message: &Message) -> Result<Message, String> {
    let (host, port) = match server.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|e| e.to_string())?),
        None => (server.to_string(), 853),
    };
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| "bad server name".to_string())?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls: {e}"))?;

    let wire = crate::wire::build(message);
    let len = u16::try_from(wire.len()).map_err(|_| "query too large".to_string())?;
    tls.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    tls.write_all(&wire)
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut hdr = [0u8; 2];
    tls.read_exact(&mut hdr)
        .await
        .map_err(|e| format!("read: {e}"))?;
    let resp_len = usize::from(u16::from_be_bytes(hdr));
    let mut body = vec![0u8; resp_len];
    tls.read_exact(&mut body)
        .await
        .map_err(|e| format!("read: {e}"))?;
    parse(&body).map_err(|e| e.to_string())
}
