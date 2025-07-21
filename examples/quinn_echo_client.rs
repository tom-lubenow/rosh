//! Minimal QUIC echo client for testing

use anyhow::Result;
use quinn::{ClientConfig, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    // Install default crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    // Enable logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();

    let server_addr: SocketAddr = "127.0.0.1:2022".parse()?;
    
    // Skip certificate validation for testing
    #[derive(Debug)]
    struct SkipVerification;
    impl rustls::client::danger::ServerCertVerifier for SkipVerification {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }
    
    // Create client config
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"echo".to_vec()];
    
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?
    ));
    
    // Create endpoint
    println!("Creating QUIC client");
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    println!("Client endpoint created at {}", endpoint.local_addr()?);
    
    // Connect to server
    println!("Connecting to {}...", server_addr);
    let connection = endpoint.connect(server_addr, "localhost")?.await?;
    println!("Connected!");
    
    // Open a stream
    let (mut send, mut recv) = connection.open_bi().await?;
    println!("Stream opened");
    
    // Send data
    let msg = b"Hello, QUIC!";
    send.write_all(msg).await?;
    send.finish()?;
    println!("Sent: {:?}", std::str::from_utf8(msg)?);
    
    // Receive echo
    let mut buf = vec![0u8; 1024];
    let n = recv.read(&mut buf).await?.unwrap_or(0);
    println!("Received: {:?}", std::str::from_utf8(&buf[..n])?);
    
    // Close
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    
    Ok(())
}