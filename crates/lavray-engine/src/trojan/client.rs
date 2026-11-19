// SPDX-License-Identifier: GPL-3.0-only

//! Trojan-клиент (spec trojan-gfw): TLS-канал (rustls) → префикс
//! hex(SHA224(password)) CRLF + адрес цели SOCKS5-байтами + CRLF → данные
//! открытым текстом внутри TLS. Своего шифра нет — конфиденциальность
//! даёт TLS; хэш-пароль отличает легитимный трафик от HTTPS-зонда.

use tokio::net::TcpStream;

use crate::addr::TargetAddr;
use crate::relay::{UpRead, UpWrite};
use crate::ss::target::target_bytes;
use tokio::io::AsyncWriteExt;

/// Параметры исходящего trojan-туннеля.
#[derive(Debug, Clone)]
pub struct TrojanOutbound {
    /// Адрес trojan-сервера.
    pub server: TargetAddr,
    /// Пароль (хэшируется SHA-224 → hex).
    pub password: String,
    /// SNI для TLS (пусто — адрес сервера).
    pub sni: String,
    /// Принимать любой сертификат (некор security.allow_insecure).
    pub skip_verify: bool,
}

/// hex(SHA-224(пароль)) — 56 символов (spec trojan: CHUNK = hex(hash) CRLF).
#[must_use]
pub fn password_hex(password: &str) -> String {
    use sha2::{Digest, Sha224};
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let d = Sha224::digest(password.as_bytes());
    let mut out = String::with_capacity(56);
    for b in d {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xF) as usize] as char);
    }
    out
}

/// Установить trojan-туннель: TLS → префикс → половины.
pub async fn connect(
    o: &TrojanOutbound,
    target: &TargetAddr,
) -> std::io::Result<(UpRead, UpWrite)> {
    let tcp = TcpStream::connect((o.server.host_string().as_str(), o.server.port())).await?;
    let _ = tcp.set_nodelay(true);
    let mut tls = crate::tls::connect(
        tcp,
        &crate::tls::TlsDial {
            sni: o.sni.clone(),
            skip_verify: o.skip_verify,
        },
        &o.server.host_string(),
    )
    .await?;

    // Префикс: hex-хэш CRLF адрес CRLF.
    let mut hello = Vec::with_capacity(56 + 2 + 7 + 2);
    hello.extend_from_slice(password_hex(&o.password).as_bytes());
    hello.extend_from_slice(b"\r\n");
    hello.extend_from_slice(&target_bytes(target));
    hello.extend_from_slice(b"\r\n");
    tls.write_all(&hello).await?;

    let (r, w) = tokio::io::split(tls);
    Ok((Box::pin(r), Box::pin(w)))
}
