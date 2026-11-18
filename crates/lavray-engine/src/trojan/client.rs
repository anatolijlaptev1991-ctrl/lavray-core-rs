// SPDX-License-Identifier: GPL-3.0-only

//! Trojan-клиент (spec trojan-gfw): TLS-канал (rustls) → префикс
//! hex(SHA224(password)) CRLF + адрес цели SOCKS5-байтами + CRLF → данные
//! открытым текстом внутри TLS. Своего шифра нет — конфиденциальность
//! даёт TLS; хэш-пароль отличает легитимный трафик от HTTPS-зонда.

use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

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

/// Верификатор «принимать всё» (только при skip_verify).
#[derive(Debug)]
struct NoVerify(Arc<tokio_rustls::rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
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
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let cfg: ClientConfig = if o.skip_verify {
        // некор security.allow_insecure: любой сертификат (осознанный риск).
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| std::io::Error::other(format!("tls версии: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))))
            .with_no_client_auth()
    } else {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| std::io::Error::other(format!("tls версии: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    let connector = TlsConnector::from(Arc::new(cfg));

    let host = o.server.host_string();
    let tcp = TcpStream::connect((host.as_str(), o.server.port())).await?;
    let sni = if o.sni.is_empty() {
        ServerName::try_from(o.server.host_string())
            .map_err(|e| std::io::Error::other(format!("sni: {e}")))?
    } else {
        ServerName::try_from(o.sni.clone())
            .map_err(|e| std::io::Error::other(format!("sni: {e}")))?
    };
    let mut tls = connector.connect(sni, tcp).await?;

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
