// SPDX-License-Identifier: GPL-3.0-only

//! Общий TLS-коннектор клиента (rustls): skip_verify = некор
//! security.allow_insecure, иначе системные корни webpki-roots.

use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

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

/// Параметры TLS-соединения.
#[derive(Debug, Clone, Default)]
pub struct TlsDial {
    /// SNI (пусто — хост сервера).
    pub sni: String,
    /// Принимать любой сертификат (allow_insecure).
    pub skip_verify: bool,
}

/// Установить TLS поверх TCP.
pub async fn connect(
    tcp: TcpStream,
    dial: &TlsDial,
    fallback_host: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let cfg = if dial.skip_verify {
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| std::io::Error::other(format!("tls версии: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| std::io::Error::other(format!("tls версии: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    let connector = TlsConnector::from(Arc::new(cfg));
    let sni = if dial.sni.is_empty() {
        fallback_host
    } else {
        &dial.sni
    };
    let name = ServerName::try_from(sni.to_string())
        .map_err(|e| std::io::Error::other(format!("sni: {e}")))?;
    connector.connect(name, tcp).await
}
