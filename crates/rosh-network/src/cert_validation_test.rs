#[cfg(test)]
mod tests {
    use crate::cert_validation::{create_cert_verifier, CertValidationMode};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    #[test]
    fn test_skip_validation_verifier() {
        let verifier = create_cert_verifier(CertValidationMode::SkipValidation).unwrap();

        // Create a dummy certificate
        let cert = CertificateDer::from(vec![0u8; 100]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::now();

        // Should accept any certificate
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], now);

        assert!(result.is_ok());
    }

    #[test]
    fn test_system_roots_verifier() {
        let _verifier = create_cert_verifier(CertValidationMode::SystemRoots).unwrap();

        // Just check that we can create it
        // Actual verification would require a real certificate chain
        // The verifier exists if we got here without panicking
    }

    #[test]
    fn test_pinned_cert_verifier() {
        // Create a test certificate
        let cert_data = b"test certificate data";
        let cert = CertificateDer::from(cert_data.to_vec());

        // For now, use the certificate bytes directly as the "fingerprint"
        // TODO: Implement proper SHA256 fingerprint calculation
        let fingerprint = cert_data.to_vec();

        // Create verifier with this fingerprint
        let verifier =
            create_cert_verifier(CertValidationMode::PinnedCertificate(fingerprint)).unwrap();

        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::now();

        // Should accept the pinned certificate
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], now);

        assert!(result.is_ok());

        // Should reject a different certificate
        let wrong_cert = CertificateDer::from(b"different certificate".to_vec());
        let result = verifier.verify_server_cert(&wrong_cert, &[], &server_name, &[], now);

        assert!(result.is_err());
    }

    #[test]
    fn test_custom_ca_verifier() {
        // Generate a self-signed certificate to use as CA
        let ca_cert = rcgen::generate_simple_self_signed(vec!["ca.example.com".to_string()])
            .expect("Failed to generate CA cert");
        let ca_cert_der = ca_cert.cert.der().to_vec();

        // Try to create verifier with custom CA
        let result = create_cert_verifier(CertValidationMode::CustomCA(ca_cert_der));

        // Should succeed in creating the verifier
        assert!(result.is_ok());
    }

    #[test]
    fn test_cert_validation_mode_default() {
        let mode = CertValidationMode::default();
        // Always skip validation since we bootstrap over SSH and have our own crypto
        assert!(matches!(mode, CertValidationMode::SkipValidation));
    }
}
