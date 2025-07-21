//! Minimal QUIC echo server for testing

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
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();

    let addr: SocketAddr = "127.0.0.1:2022".parse()?;
    
    // Generate self-signed certificate
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
    server_crypto.alpn_protocols = vec![b"echo".to_vec()];
    
    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?
    ));
    
    // Create endpoint
    println!("Starting QUIC echo server on {}", addr);
    let endpoint = Endpoint::server(server_config, addr)?;
    println!("Server listening on {}", endpoint.local_addr()?);
    
    // Accept connections
    while let Some(connecting) = endpoint.accept().await {
        println!("Connection incoming...");
        tokio::spawn(async move {
            match connecting.await {
                Ok(connection) => {
                    println!("Connection established from {}", connection.remote_address());
                    handle_connection(connection).await;
                }
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                }
            }
        });
    }
    
    Ok(())
}

async fn handle_connection(connection: quinn::Connection) {
    loop {
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                println!("Stream opened");
                
                // Echo received data
                let mut buf = vec![0u8; 1024];
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => {
                        println!("Received {} bytes", n);
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            eprintln!("Failed to echo: {}", e);
                        }
                        let _ = send.finish();
                    }
                    Ok(None) => {
                        println!("Stream closed by peer");
                    }
                    Err(e) => {
                        eprintln!("Failed to read: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("Connection closed: {}", e);
                break;
            }
        }
    }
}