//! QUIC transport implementation for Rosh
//! 
//! Uses Quinn for QUIC protocol support, providing:
//! - Automatic connection migration (roaming)
//! - Built-in congestion control
//! - Stream multiplexing
//! - 0-RTT resumption

use crate::NetworkError;
use quinn::{
    ClientConfig, Endpoint, ServerConfig,
    Connection, RecvStream, SendStream,
    VarInt, congestion,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

/// ALPN protocol identifier for Rosh
const ALPN_ROSH: &[u8] = b"rosh/1";

/// Configuration for transport layer
#[derive(Debug, Clone)]
pub struct RoshTransportConfig {
    /// Keep-alive interval (0 to disable)
    pub keep_alive_interval: Duration,
    /// Maximum idle timeout before closing connection
    pub max_idle_timeout: Duration,
    /// Initial congestion window in packets
    pub initial_window: u32,
    /// Stream receive window
    pub stream_receive_window: VarInt,
}

impl Default for RoshTransportConfig {
    fn default() -> Self {
        Self {
            keep_alive_interval: Duration::from_secs(5),
            max_idle_timeout: Duration::from_secs(30),
            initial_window: 20, // packets
            stream_receive_window: VarInt::from_u32(1024 * 1024), // 1 MB
        }
    }
}

/// Client transport endpoint
pub struct ClientTransport {
    endpoint: Endpoint,
    connection: Option<Connection>,
}

impl ClientTransport {
    /// Create a new client transport
    pub async fn new(config: RoshTransportConfig) -> Result<Self, NetworkError> {
        let _client_config = create_client_config(config)?;
        
        // Bind to any available port
        let endpoint = Endpoint::client("[::]:0".parse().unwrap())
            .map_err(|e| NetworkError::TransportError(format!("Failed to create endpoint: {}", e)))?;
        
        Ok(Self {
            endpoint,
            connection: None,
        })
    }
    
    /// Connect to a server
    pub async fn connect(&mut self, addr: SocketAddr) -> Result<(), NetworkError> {
        let client_config = create_client_config(RoshTransportConfig::default())?;
        
        let connection = self.endpoint
            .connect_with(client_config, addr, "localhost")
            .map_err(|e| NetworkError::ConnectionFailed(format!("Failed to initiate connection: {}", e)))?
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("Connection failed: {}", e)))?;
            
        self.connection = Some(connection);
        Ok(())
    }
    
    /// Open a new bidirectional stream
    pub async fn open_stream(&self) -> Result<(SendStream, RecvStream), NetworkError> {
        let connection = self.connection
            .as_ref()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;
            
        connection.open_bi().await
            .map_err(|e| NetworkError::TransportError(format!("Failed to open stream: {}", e)))
    }
    
    /// Get the current connection state
    pub fn is_connected(&self) -> bool {
        self.connection.as_ref().map(|c| !c.close_reason().is_some()).unwrap_or(false)
    }
    
    /// Get connection statistics
    pub fn stats(&self) -> Option<quinn::ConnectionStats> {
        self.connection.as_ref().map(|c| c.stats())
    }
}

/// Server transport endpoint
pub struct ServerTransport {
    endpoint: Endpoint,
}

impl ServerTransport {
    /// Create a new server transport
    pub async fn new(bind_addr: SocketAddr, config: RoshTransportConfig) -> Result<Self, NetworkError> {
        let (server_config, _) = create_server_config(config)?;
        
        let endpoint = Endpoint::server(server_config, bind_addr)
            .map_err(|e| NetworkError::TransportError(format!("Failed to create server endpoint: {}", e)))?;
            
        Ok(Self { endpoint })
    }
    
    /// Accept incoming connections
    pub async fn accept(&self) -> Result<IncomingConnection, NetworkError> {
        let connecting = self.endpoint
            .accept()
            .await
            .ok_or_else(|| NetworkError::TransportError("Server endpoint closed".to_string()))?;
            
        let connection = connecting.await
            .map_err(|e| NetworkError::ConnectionFailed(format!("Failed to accept connection: {}", e)))?;
            
        Ok(IncomingConnection { connection })
    }
    
    /// Get the server's bound address
    pub fn local_addr(&self) -> Result<SocketAddr, NetworkError> {
        self.endpoint.local_addr()
            .map_err(|e| NetworkError::TransportError(format!("Failed to get local address: {}", e)))
    }
}

/// An accepted incoming connection
pub struct IncomingConnection {
    connection: Connection,
}

impl IncomingConnection {
    /// Accept a bidirectional stream
    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream), NetworkError> {
        self.connection.accept_bi().await
            .map_err(|e| NetworkError::TransportError(format!("Failed to accept stream: {}", e)))
    }
    
    /// Get the remote address
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }
    
    /// Get connection statistics
    pub fn stats(&self) -> quinn::ConnectionStats {
        self.connection.stats()
    }
}

/// Create client configuration
fn create_client_config(config: RoshTransportConfig) -> Result<ClientConfig, NetworkError> {
    // For development, accept any certificate
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    
    client_crypto.alpn_protocols = vec![ALPN_ROSH.to_vec()];
    
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| NetworkError::TransportError(format!("Failed to create QUIC client config: {}", e)))?
    ));
    
    client_config.transport_config(Arc::new(create_transport_config(config)));
    
    Ok(client_config)
}

/// Create server configuration with self-signed certificate
fn create_server_config(config: RoshTransportConfig) -> Result<(ServerConfig, CertificateDer<'static>), NetworkError> {
    // Generate self-signed certificate
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| NetworkError::TransportError(format!("Failed to generate certificate: {}", e)))?;
        
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .map_err(|e| NetworkError::TransportError(format!("Failed to create server crypto config: {}", e)))?;
        
    server_crypto.alpn_protocols = vec![ALPN_ROSH.to_vec()];
    
    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| NetworkError::TransportError(format!("Failed to create QUIC server config: {}", e)))?
    ));
    
    server_config.transport_config(Arc::new(create_transport_config(config)));
    
    Ok((server_config, cert_der))
}

/// Create QUIC transport configuration
fn create_transport_config(config: RoshTransportConfig) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    
    transport.max_idle_timeout(Some(config.max_idle_timeout.try_into().unwrap()));
    transport.keep_alive_interval(Some(config.keep_alive_interval));
    
    // Set congestion control parameters
    transport.initial_rtt(Duration::from_millis(100));
    transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
    
    // Set flow control windows
    transport.stream_receive_window(config.stream_receive_window);
    transport.receive_window(config.stream_receive_window);
    
    // Set initial congestion window
    let mut cc_config = congestion::BbrConfig::default();
    cc_config.initial_window(config.initial_window as u64);
    transport.congestion_controller_factory(Arc::new(cc_config));
    
    transport
}

/// Skip certificate verification for development
/// TODO: Implement proper certificate validation for production
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
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