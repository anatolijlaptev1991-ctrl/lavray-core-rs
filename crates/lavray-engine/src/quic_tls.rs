// SPDX-License-Identifier: GPL-3.0-only

//! QUIC TLS-конфиг клиента (hy2/tuic): webpki-roots или skip_verify
//! (parity Go `tls.Config{InsecureSkipVerify: true}`). quinn-овый
//! `QuicClientConfig::try_from` вычисляет initial suite из
//! crypto_provider и от верификатора не зависит.

use std::sync::Arc;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// Верификатор «доверять всем» — только при явном skip_verify профиля.
#[derive(Debug)]
pub struct SkipVerify;

impl ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Клиентский QUIC-конфиг: `skip_verify` → dangerous-верификатор
/// (TLS 1.3), иначе webpki-roots; ALPN = `h3` (QUIC-протоколы Go-эталона).
///
/// # Errors
/// Провайдер без QUIC-suite / неверная версия TLS / не подходящий ALPN.
pub fn client_config(skip_verify: bool, alpn: &[&str]) -> Result<quinn::ClientConfig, String> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let versions = &[&tokio_rustls::rustls::version::TLS13];
    let mut tls = if skip_verify {
        tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| format!("tls13: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerify))
            .with_no_client_auth()
    } else {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| format!("tls13: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|e| format!("quic initial suite: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_verify_config_builds() {
        let cfg = client_config(true, &["h3"]).expect("skip_verify config");
        let _ = cfg;
    }

    #[test]
    fn roots_config_builds() {
        let cfg = client_config(false, &["h3"]).expect("roots config");
        let _ = cfg;
    }
}
