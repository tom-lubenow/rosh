//! Minimal server that mimics Rosh's structure more closely

use anyhow::Result;
use quinn::{Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    // Install default crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    // Enable logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .init();

    let addr: SocketAddr = "0.0.0.0:2022".parse()?;
    
    // Generate self-signed certificate (like Rosh)
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().clone();
    let key_der = cert.key_pair.serialize_der();
    
    // Create server config
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der).into()
        )?;
    server_crypto.alpn_protocols = vec![b"rosh/1".to_vec()];
    
    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?
    ));
    
    // Add transport config to match Rosh
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(90_000).into()));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(30)));
    server_config.transport_config(Arc::new(transport));
    
    // Create endpoint
    tracing::info!("Creating server endpoint at {}", addr);
    let endpoint = Endpoint::server(server_config, addr)?;
    tracing::info!("Server listening on {}", endpoint.local_addr()?);
    
    // Accept loop (mimicking Rosh's transport.accept())
    tracing::info!("Waiting for incoming QUIC connection...");
    
    if let Some(connecting) = endpoint.accept().await {
        tracing::info!("QUIC connection incoming...");
        match connecting.await {
            Ok(connection) => {
                tracing::info!("QUIC connection established from {}", connection.remote_address());
                
                // Wait for client to open a stream (like Rosh)
                tracing::info!("Waiting for client to open stream...");
                match connection.accept_bi().await {
                    Ok((mut send, mut recv)) => {
                        tracing::info!("Stream opened by client");
                        
                        // Echo test
                        let mut buf = vec![0u8; 1024];
                        match recv.read(&mut buf).await {
                            Ok(Some(n)) => {
                                tracing::info!("Received {} bytes", n);
                                send.write_all(&buf[..n]).await?;
                                send.finish()?;
                            }
                            Ok(None) => tracing::info!("Stream closed by client"),
                            Err(e) => tracing::error!("Read error: {}", e),
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept stream: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Connection failed: {}", e);
            }
        }
    }
    
    Ok(())
}