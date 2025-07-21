use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use std::sync::Arc;

/// Install the default crypto provider for QUIC/TLS
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Certificate validation mode for Rosh
#[derive(Debug, Clone, Default)]
pub enum CertValidationMode {
    /// Skip all certificate validation (DANGEROUS - development only)
    #[default]
    SkipValidation,
    /// Validate using system root certificates
    SystemRoots,
    /// Validate using a specific CA certificate
    CustomCA(Vec<u8>),
    /// Validate using a pinned certificate fingerprint
    PinnedCertificate(Vec<u8>),
}

/// Create a certificate verifier based on the validation mode
pub fn create_cert_verifier(
    mode: CertValidationMode,
) -> Result<Arc<dyn ServerCertVerifier>, RustlsError> {
    match mode {
        CertValidationMode::SkipValidation => {
            tracing::warn!("Certificate validation is disabled - this is insecure!");
            Ok(Arc::new(SkipServerVerification))
        }
        CertValidationMode::SystemRoots => {
            // For now, skip validation until we add platform verifier
            // TODO: Add rustls-platform-verifier or webpki-roots dependency
            tracing::warn!("System root validation not yet implemented, skipping validation");
            Ok(Arc::new(SkipServerVerification))
        }
        CertValidationMode::CustomCA(ca_cert) => {
            // Parse the CA certificate
            let ca_cert = CertificateDer::from(ca_cert);
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(ca_cert).map_err(|_e| {
                RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;

            // Create a verifier with the custom CA
            let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|_| RustlsError::General("Failed to build verifier".to_string()))?;

            Ok(verifier)
        }
        CertValidationMode::PinnedCertificate(fingerprint) => {
            Ok(Arc::new(PinnedCertVerifier { fingerprint }))
        }
    }
}

/// Skip certificate verification (development only)
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

/// Certificate verifier that pins a specific certificate
#[derive(Debug)]
struct PinnedCertVerifier {
    fingerprint: Vec<u8>,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // For now, just compare the certificate bytes directly
        // TODO: Implement proper SHA256 fingerprint calculation
        if end_entity.as_ref() == self.fingerprint.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
